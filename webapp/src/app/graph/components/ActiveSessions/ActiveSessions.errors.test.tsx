/**
 * The Active Sessions panel shows why it is stale or empty (G-15) and why a
 * kill did not happen (G-27), and the command whisperer shows the HTTP status
 * of a non-JSON answer and the provider's class and status (G-24).
 *
 * Run: npx vitest run src/app/graph/components/ActiveSessions/ActiveSessions.errors.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }))
vi.mock('@/components/ui', async (orig) => ({ ...(await orig<typeof import('@/components/ui')>()), useToast: () => toast }))
vi.mock('./SessionTerminal', async (orig) => ({
  ...(await orig<typeof import('./SessionTerminal')>()),
  SessionTerminal: () => null,
}))

import { ActiveSessions } from './ActiveSessions'
import { whispererErrorText } from './SessionTerminal'

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

const base = {
  jobs: [], nonMsfSessions: [], agentBusy: false, isLoading: false, projectId: 'p1',
  onInteract: vi.fn(), onKillSession: vi.fn(async () => {}), onKillJob: vi.fn(async () => {}),
}
const session = { id: 7, type: 'shell', info: '', tunnel_peer: '10.0.0.1:4444', target_host: '', via_exploit: '', chat_session_id: null } as never

describe('Active Sessions errors', () => {
  test('an empty list with an error says the list could not load, not "No Reverse Shells"', () => {
    render(<ActiveSessions {...base} sessions={[]} error="Failed to fetch sessions (agent_unreachable · HTTP 503)" />)
    expect(screen.getByText('Could not load sessions')).toBeInTheDocument()
    expect(screen.getByText('Failed to fetch sessions (agent_unreachable · HTTP 503)')).toBeInTheDocument()
    expect(screen.queryByText('No Reverse Shells')).toBeNull()
  })

  test('a stale list keeps its rows and says it was not refreshed', () => {
    render(<ActiveSessions {...base} sessions={[session]} error="Failed to fetch sessions (agent_timeout · HTTP 504)" />)
    expect(screen.getByRole('alert')).toHaveTextContent('Not refreshed: Failed to fetch sessions (agent_timeout · HTTP 504)')
  })

  test('without an error the empty state is unchanged', () => {
    render(<ActiveSessions {...base} sessions={[]} />)
    expect(screen.getByText('No Reverse Shells')).toBeInTheDocument()
  })

  test('a failed kill is toasted with its cause', async () => {
    const onKillSession = vi.fn(async () => {
      throw new ApiError({ reason: 'Failed to kill session', status: 502, code: 'agent_error', upstreamStatus: 500 })
    })
    render(<ActiveSessions {...base} sessions={[session]} onKillSession={onKillSession} />)
    fireEvent.click(screen.getByTitle(/kill/i))
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith(
      'Failed to kill session (agent_error · HTTP 502 · upstream HTTP 500)', 'Session not killed',
    ))
  })

  test('a kill nobody answered in time is "not confirmed", not "not killed" (S16b review round 4)', async () => {
    for (const noAnswer of [
      new ApiError({ reason: 'Session 7: no answer in time; the kill may still complete', status: 502, code: 'agent_error', upstreamStatus: 504 }),
      new ApiError({ reason: 'Session 7: no answer in time; the kill may still complete', status: 504, code: 'agent_timeout' }),
    ]) {
      toast.error.mockClear()
      const { unmount } = render(<ActiveSessions {...base} sessions={[session]} onKillSession={vi.fn(async () => { throw noAnswer })} />)
      fireEvent.click(screen.getByTitle(/kill/i))
      await waitFor(() => expect(toast.error).toHaveBeenCalledWith(noAnswer.message, 'Kill not confirmed'))
      unmount()
    }
  })

  test('a kill the console was too busy to run stays "Session not killed"', async () => {
    const busy = new ApiError({ reason: 'Session 7 was not killed: the Kali console is busy with another command, try again', status: 200, code: 'console_busy' })
    render(<ActiveSessions {...base} sessions={[session]} onKillSession={vi.fn(async () => { throw busy })} />)
    fireEvent.click(screen.getByTitle(/kill/i))
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith(busy.message, 'Session not killed'))
  })

  test('a job stop nobody answered in time is "not confirmed" too', async () => {
    const noAnswer = new ApiError({ reason: 'Job 0: no answer in time; the stop may still complete', status: 502, code: 'agent_error', upstreamStatus: 504 })
    const job = { id: 0, name: 'Exploit: multi/handler', payload: 'p', port: 4444 } as never
    render(<ActiveSessions {...base} sessions={[session]} jobs={[job]} onKillJob={vi.fn(async () => { throw noAnswer })} />)
    fireEvent.click(screen.getByTitle('Stop job'))
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith(noAnswer.message, 'Stop not confirmed'))
  })
})

describe('command whisperer failure text (G-24)', () => {
  test('a body that is not JSON says the HTTP status', () => {
    expect(whispererErrorText(502, null)).toBe('Error 502')
  })

  test("the provider's class and status follow the agent's sentence", () => {
    expect(whispererErrorText(502, { error: 'The model call failed. Try again in a moment.', error_class: 'RateLimitError', provider_status: 429 }))
      .toBe('The model call failed. Try again in a moment. (RateLimitError · provider HTTP 429)')
  })

  test('a feature-model code keeps its own sentence', () => {
    expect(whispererErrorText(504, { error: 'x', code: 'agent_timeout' })).toBe('The model took too long, try again')
  })
})
