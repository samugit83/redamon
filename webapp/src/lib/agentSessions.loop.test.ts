/**
 * The agent's live-session answer carries the Agent in the Loop state of loop
 * runs; a reader that knows only session_ids keeps working, and the activity
 * report says when a loop run is waiting for its external agent.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ agentFetch: vi.fn(), findMany: vi.fn() }))
vi.mock('@/lib/prisma', () => ({ default: { conversation: { findMany: (...a: unknown[]) => h.findMany(...a) } } }))
vi.mock('@/lib/agentFetch', () => ({ agentFetch: (...a: unknown[]) => h.agentFetch(...a) }))

import { agentLoopWaiting, checkAgentSessions } from './agentSessions'

const answer = (body: unknown) => ({ ok: true, status: 200, json: async () => body })

beforeEach(() => {
  vi.clearAllMocks()
  h.findMany.mockResolvedValue([{ id: 'c1', sessionId: 's1', updatedAt: new Date() }])
})

describe('loop_states', () => {
  test('a loop run waiting for its agent', async () => {
    h.agentFetch.mockResolvedValue(answer({ project_id: 'p1', session_ids: ['s1'], loop_states: { s1: 'waiting_for_agent' } }))
    expect(await agentLoopWaiting('p1')).toBe(true)
  })

  test('a loop run running a tool, or a provider run, is not waiting', async () => {
    h.agentFetch.mockResolvedValue(answer({ project_id: 'p1', session_ids: ['s1'], loop_states: { s1: 'running_tool' } }))
    expect(await agentLoopWaiting('p1')).toBe(false)
    h.agentFetch.mockResolvedValue(answer({ project_id: 'p1', session_ids: ['s1'] }))
    expect(await agentLoopWaiting('p1')).toBe(false)
  })

  test('the extra key changes nothing for the running check', async () => {
    h.agentFetch.mockResolvedValue(answer({ project_id: 'p1', session_ids: ['s1'], loop_states: { s1: 'waiting_for_agent' } }))
    expect(await checkAgentSessions('p1')).toBe('running')
  })

  test('an agent that cannot be asked is not waiting', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    h.agentFetch.mockRejectedValue(new Error('down'))
    expect(await agentLoopWaiting('p1')).toBe(false)
  })
})
