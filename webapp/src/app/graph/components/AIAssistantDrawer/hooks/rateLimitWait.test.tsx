/**
 * A chat run waiting for the model provider's rate limit: the agent's
 * `rate_limit_wait` frame becomes a countdown in place of the loading word, and
 * the next sign of progress removes it.
 */
import React, { createRef } from 'react'
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, renderHook, act } from '@testing-library/react'
import { MessageType } from '@/lib/websocket-types'
import { ChatArea } from '../ChatArea'
import {
  endsRateLimitWait,
  rateLimitWaitFromPayload,
  rateLimitWaitText,
  useRateLimitWait,
  useRateLimitWaitText,
  type RateLimitWait,
} from './rateLimitWait'
import { useWebSocketHandler } from './useWebSocketHandler'

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

const NOW = 1_700_000_000_000

describe('the frame', () => {
  test('a valid frame becomes a wait ending `seconds` from now', () => {
    expect(rateLimitWaitFromPayload({ seconds: 16, retry: 3, purpose: 'report' }, NOW))
      .toEqual({ until: NOW + 16_000, seconds: 16, retry: 3, purpose: 'report' })
  })

  test('a malformed frame shows nothing, an odd purpose shows a generic one', () => {
    for (const bad of [null, {}, { seconds: -1, retry: 1 }, { seconds: '16', retry: 1 },
      { seconds: Number.NaN, retry: 1 }, { seconds: 16, retry: 0 }, { seconds: 7200, retry: 1 }]) {
      expect(rateLimitWaitFromPayload(bad, NOW)).toBeNull()
    }
    expect(rateLimitWaitFromPayload({ seconds: 5, retry: 1, purpose: '<b>x</b>' }, NOW)?.purpose).toBe('other')
  })
})

describe('the countdown', () => {
  const wait: RateLimitWait = { until: NOW + 16_000, seconds: 16, retry: 2, purpose: 'report' }

  test('names the call and counts down to the retry', () => {
    expect(rateLimitWaitText(wait, NOW)).toBe('Provider rate limit: retrying the summary in 16 s')
    expect(rateLimitWaitText(wait, NOW + 10_500)).toBe('Provider rate limit: retrying the summary in 6 s')
    expect(rateLimitWaitText(wait, NOW + 16_000)).toBe('Provider rate limit: retrying the summary now')
    expect(rateLimitWaitText({ ...wait, purpose: 'other' }, NOW)).toBe('Provider rate limit: retrying the model call in 16 s')
    expect(rateLimitWaitText(null, NOW)).toBeNull()
  })

  test('a clock older than the frame never shows more than the wait', () => {
    expect(rateLimitWaitText(wait, NOW - 300_000)).toBe('Provider rate limit: retrying the summary in 16 s')
  })

  test('the hook ticks every second while a wait is shown', () => {
    vi.useFakeTimers()
    vi.setSystemTime(NOW)
    const live: RateLimitWait = { until: NOW + 3_000, seconds: 3, retry: 1, purpose: 'think' }
    const { result } = renderHook(() => useRateLimitWaitText(live))
    expect(result.current).toBe('Provider rate limit: retrying the next step in 3 s')
    act(() => { vi.advanceTimersByTime(1_000) })
    expect(result.current).toBe('Provider rate limit: retrying the next step in 2 s')
    act(() => { vi.advanceTimersByTime(2_000) })
    expect(result.current).toBe('Provider rate limit: retrying the next step now')
  })
})

describe('the drawer state', () => {
  const frame = { seconds: 16, retry: 1, purpose: 'report' }

  test('a wait from a run that stopped loading without a frame does not come back', () => {
    const { result, rerender } = renderHook(({ loading, session }) => useRateLimitWait(loading, session),
      { initialProps: { loading: true, session: 's1' } })
    act(() => { result.current.setRateLimitWait(rateLimitWaitFromPayload(frame, Date.now())) })
    expect(result.current.rateLimitWord).toMatch(/^Provider rate limit: retrying the summary/)
    rerender({ loading: false, session: 's1' })
    rerender({ loading: true, session: 's1' })
    expect(result.current.rateLimitWord).toBeNull()
  })

  test('a new session drops the wait', () => {
    const { result, rerender } = renderHook(({ loading, session }) => useRateLimitWait(loading, session),
      { initialProps: { loading: true, session: 's1' } })
    act(() => { result.current.setRateLimitWait(rateLimitWaitFromPayload(frame, Date.now())) })
    rerender({ loading: true, session: 's2' })
    expect(result.current.rateLimitWord).toBeNull()
  })
})

describe('the handler', () => {
  function handler() {
    const setRateLimitWait = vi.fn()
    const noop = vi.fn()
    const ref = { current: false }
    const { result } = renderHook(() => useWebSocketHandler({
      setChatItems: noop, setIsLoading: noop, setIsStopped: noop, setIsStopping: noop,
      setCurrentPhase: noop, setIterationCount: noop, setAttackPathType: noop, setTodoList: noop,
      todoList: [], itemIdCounter: { current: 0 },
      setAwaitingApproval: noop, setApprovalRequest: noop, setAwaitingQuestion: noop, setQuestionRequest: noop,
      setAwaitingToolConfirmation: noop, setToolConfirmationRequest: noop,
      awaitingApprovalRef: ref, isProcessingApproval: ref, awaitingQuestionRef: ref, isProcessingQuestion: ref,
      awaitingToolConfirmationRef: ref, isProcessingToolConfirmation: ref,
      pendingApprovalToolId: { current: null }, pendingApprovalWaveId: { current: null },
      setRateLimitWait,
    } as never))
    const send = (type: MessageType, payload: unknown) =>
      act(() => result.current.handleWebSocketMessage({ type, payload, timestamp: 't' } as never))
    return { send, setRateLimitWait }
  }

  test('a wait frame shows the wait and is not added to the chat', () => {
    const h = handler()
    h.send(MessageType.RATE_LIMIT_WAIT, { seconds: 8, retry: 1, purpose: 'think' })
    expect(h.setRateLimitWait).toHaveBeenLastCalledWith(
      expect.objectContaining({ seconds: 8, retry: 1, purpose: 'think' }))
  })

  test('progress ends the wait; a pong or a background job does not', () => {
    const h = handler()
    h.send(MessageType.RATE_LIMIT_WAIT, { seconds: 8, retry: 1, purpose: 'think' })
    h.setRateLimitWait.mockClear()
    h.send(MessageType.PONG, {})
    h.send(MessageType.JOB_UPDATE, {})
    expect(h.setRateLimitWait).not.toHaveBeenCalled()
    h.send(MessageType.THINKING, { iteration: 1, phase: 'informational', thought: 't', reasoning: 'r' })
    expect(h.setRateLimitWait).toHaveBeenLastCalledWith(null)
  })

  test('which messages end a wait', () => {
    for (const type of [MessageType.THINKING, MessageType.TOOL_START, MessageType.RESPONSE,
      MessageType.ERROR, MessageType.TASK_COMPLETE, MessageType.STOPPED, MessageType.FIRETEAM_THINKING]) {
      expect(endsRateLimitWait(type)).toBe(true)
    }
    for (const type of [MessageType.RATE_LIMIT_WAIT, MessageType.PONG, MessageType.CONNECTED,
      MessageType.JOB_UPDATE, MessageType.LOOP_STATUS]) {
      expect(endsRateLimitWait(type)).toBe(false)
    }
  })
})

describe('the drawer', () => {
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
        openApiKeyModal={() => {}}
        handleTimelineToolConfirmation={() => {}}
        {...props}
      />,
    )
  }

  test('the countdown replaces the loading word', () => {
    renderChat({ rateLimitWord: 'Provider rate limit: retrying the summary in 12 s' })
    expect(screen.getByText('Provider rate limit: retrying the summary in 12 s')).toBeInTheDocument()
    expect(screen.queryByText('Pondering')).toBeNull()
  })

  test('without a wait the loading word stays', () => {
    renderChat({ rateLimitWord: null })
    expect(screen.getByText('Pondering')).toBeInTheDocument()
  })
})
