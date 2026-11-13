/**
 * Who is running an agent session on a project (step 5.11): the authors of the flagged sessions
 * the agent confirms live, for the second-writer check. Read-only, and the agent is asked only
 * when a flag is set, as checkAgentSessions does.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findMany: vi.fn(),
  updateMany: vi.fn(),
  agentFetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: { conversation: { findMany: h.findMany, updateMany: h.updateMany } },
}))
vi.mock('@/lib/agentFetch', () => ({ agentFetch: (...a: unknown[]) => h.agentFetch(...a) }))

import { runningSessionAuthors } from './agentSessions'

const live = (ids: unknown) => ({ ok: true, json: async () => ({ project_id: 'p1', session_ids: ids }) })

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  h.findMany.mockResolvedValue([])
  h.agentFetch.mockResolvedValue(live([]))
})

describe('runningSessionAuthors', () => {
  test('no flag set: nobody, and the agent is never asked', async () => {
    expect(await runningSessionAuthors('p1')).toEqual({ userIds: [] })
    expect(h.agentFetch).not.toHaveBeenCalled()
    expect(h.findMany).toHaveBeenCalledWith({ where: { projectId: 'p1', agentRunning: true }, select: { userId: true, sessionId: true } })
  })

  test('the authors of the sessions the agent confirms, once each', async () => {
    h.findMany.mockResolvedValue([
      { userId: 'bob', sessionId: 's1' }, { userId: 'bob', sessionId: 's2' }, { userId: 'olivia', sessionId: 's3' },
    ])
    h.agentFetch.mockResolvedValue(live(['s1', 's2', 's3']))
    expect(await runningSessionAuthors('p1')).toEqual({ userIds: ['bob', 'olivia'] })
    expect(h.agentFetch.mock.calls[0][0]).toBe('/agent-sessions/live?project_id=p1')
  })

  test('a stale flag names nobody and is left for checkAgentSessions to clear', async () => {
    h.findMany.mockResolvedValue([{ userId: 'bob', sessionId: 's1' }])
    h.agentFetch.mockResolvedValue(live(['other']))
    expect(await runningSessionAuthors('p1')).toEqual({ userIds: [] })
    expect(h.updateMany).not.toHaveBeenCalled()
  })

  test('an agent that cannot answer is a failure, never "nobody"', async () => {
    h.findMany.mockResolvedValue([{ userId: 'bob', sessionId: 's1' }])
    h.agentFetch.mockRejectedValue(new Error('ECONNREFUSED'))
    expect(await runningSessionAuthors('p1')).toEqual({ failure: expect.objectContaining({ code: expect.stringMatching(/^agent_/) }) })
    h.agentFetch.mockResolvedValue({ ok: false, status: 502, json: async () => ({}) })
    expect(await runningSessionAuthors('p1')).toEqual({ failure: { code: 'agent_error', upstreamStatus: 502 } })
  })
})
