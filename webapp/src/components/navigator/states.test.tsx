/**
 * Every row of the loading, error and partial states table (plan §9.14): the sentence each code
 * shows, from the one module the panel reads, and the partial answers live and reopened: stopped,
 * failed, a question with no answer after it, and Retry on the last turn only.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { featureModelMessage } from '@/lib/llmFeatures'
import { ChatView } from './views/ChatView'
import { navigatorMessage } from './messages'
import type { ChatMessage } from './useNavigatorChat'

afterEach(cleanup)

describe('the sentence for each code', () => {
  test.each([
    ['rate_limited', { retryAfterSeconds: 42 }, "You're sending messages too fast. Try again in 42 s."],
    ['busy', {}, 'An answer is already being written for you on this project, maybe in another tab.'],
    ['thread_full', {}, 'This conversation is full. Start a new one.'],
    ['too_many_threads', {}, 'You have too many conversations on this project. Delete some in History.'],
    ['project_busy', {}, 'This project is being restored or transferred. Try again in a minute.'],
    ['agent_unreachable', {}, "AI Navigator's service isn't reachable right now."],
    ['timeout', {}, "AI Navigator's service isn't reachable right now."],
    ['agent_busy', {}, 'AI Navigator is busy right now. Try again in a moment.'],
    ['agent_outdated', {}, 'The agent is older than the web app. Rebuild it with ./redamon.sh update.'],
    ['navigator_unavailable', {}, "AI Navigator isn't configured on this server. Ask your administrator to run ./redamon.sh update."],
    ['something_new', {}, 'Something went wrong (something_new).'],
  ])('%s', (code, extra, text) => {
    expect(navigatorMessage(code, extra)).toBe(text)
  })

  test('no code at all names the HTTP status', () => {
    expect(navigatorMessage(null, { status: 502 })).toBe('Something went wrong (HTTP 502).')
  })

  test('a model code nothing here overrides reads the feature-model sentence', () => {
    expect(navigatorMessage('model_required')).toBe(featureModelMessage('model_required'))
  })
})

let seq = 0
const msg = (over: Partial<ChatMessage>): ChatMessage => ({
  id: `m-${(seq += 1)}`, role: 'assistant', content: '', status: 'complete', routes: [], citations: [], trace: [],
  errorCode: null, ...over,
})
const q = (content: string, id = `u-${content}`) => msg({ id, role: 'user', content })

function show(messages: ChatMessage[]) {
  const onRetry = vi.fn()
  render(<ChatView messages={messages} onRetry={onRetry} onOpenAgent={() => {}} agentAllowed empty={<p>empty</p>} />)
  return onRetry
}

describe('partial and failed answers', () => {
  test('stopped keeps its text with a tag; failed shows its text and why', () => {
    show([q('one'), msg({ content: 'half an answer', status: 'stopped' }), q('two'), msg({ content: 'some', status: 'failed', errorCode: 'model_error' })])
    expect(screen.getByText('half an answer')).toBeTruthy()
    expect(screen.getByText('Stopped')).toBeTruthy()
    expect(screen.getByText('Failed: The model call failed. Try again in a moment.')).toBeTruthy()
  })

  test('Retry on the last turn only, and it sends the previous question again', () => {
    const onRetry = show([q('first'), msg({ status: 'failed', errorCode: 'agent_unreachable' }), q('second'), msg({ status: 'failed', errorCode: 'agent_unreachable' })])
    const retries = screen.getAllByRole('button', { name: 'Retry' })
    expect(retries).toHaveLength(1)
    fireEvent.click(retries[0])
    expect(onRetry).toHaveBeenCalledWith('second')
  })

  test('a question with no answer after it says so, anywhere; only the last offers Retry', () => {
    const onRetry = show([q('lost in a restart'), q('and the latest')])
    expect(screen.getAllByText(/No answer was saved\./)).toHaveLength(2)
    const retries = screen.getAllByRole('button', { name: 'Retry' })
    expect(retries).toHaveLength(1)
    fireEvent.click(retries[0])
    expect(onRetry).toHaveBeenCalledWith('and the latest')
  })

  test('a question being sent right now is not "unanswered"', () => {
    show([q('just sent', 'local-user-1'), msg({ id: 'local-answer-1', status: 'streaming' })])
    expect(screen.queryByText(/No answer was saved/)).toBeNull()
  })
})
