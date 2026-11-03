/**
 * Deleting a project stops its live chat runs first (Q17), for every model: an
 * orphan run of a deleted project is wrong whatever its brain, and an Agent in
 * the Loop run would keep offering steps to the owner's agent. Best-effort.
 *
 * Same harness as route.delete.test.ts, plus the conversations and the agent.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  projectDelete: vi.fn(),
  jobQueueUpdateMany: vi.fn(),
  capturedFindMany: vi.fn(),
  orchestratorFetch: vi.fn(),
  effectiveUser: vi.fn(),
  countAuthorizations: vi.fn(),
  archiveTransaction: vi.fn(),
  purgeWorkspace: vi.fn(),
  runningChats: vi.fn(),
  agentFetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { delete: (...a: unknown[]) => h.projectDelete(...a) },
    jobQueue: { updateMany: (...a: unknown[]) => h.jobQueueUpdateMany(...a) },
    capturedHttpTransaction: { findMany: (...a: unknown[]) => h.capturedFindMany(...a) },
    // The authorization records do NOT cascade: they are archived first, so
    // deleting a project cannot destroy the record of what authorized it.
    engagementAuthorization: { count: (...a: unknown[]) => h.countAuthorizations(...a) },
    $transaction: (fn: (tx: unknown) => unknown) => h.archiveTransaction(fn),
    conversation: { findMany: (...a: unknown[]) => h.runningChats(...a) },
  },
}))
vi.mock('@/lib/agentFetch', async () => ({
  ...(await vi.importActual<typeof import('@/lib/agentFetch')>('@/lib/agentFetch')),
  agentFetch: (...a: unknown[]) => h.agentFetch(...a),
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/workspacePurge', () => ({ purgeProjectWorkspace: (...a: unknown[]) => h.purgeWorkspace(...a) }))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: () => h.effectiveUser(), requireProjectAccess: () => null }
})

import { DELETE } from './route'

const del = () => new NextRequest('http://x/api/projects/p1', { method: 'DELETE' })
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.effectiveUser.mockResolvedValue({ userId: 'u1' })
  h.projectDelete.mockResolvedValue({ id: 'p1', userId: 'u1' })
  h.jobQueueUpdateMany.mockResolvedValue({ count: 2 })
  h.capturedFindMany.mockResolvedValue([])
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ deleted: [] }) })
  h.countAuthorizations.mockResolvedValue(0)
  h.archiveTransaction.mockImplementation(async (fn: (tx: unknown) => unknown) =>
    fn({ $executeRawUnsafe: async () => 1 })
  )
  h.purgeWorkspace.mockResolvedValue(undefined)
  h.runningChats.mockResolvedValue([])
  h.agentFetch.mockResolvedValue({ ok: true, status: 200 })
})

describe('deleting a project stops its running chats', () => {
  const stopBodies = () => h.agentFetch.mock.calls
    .filter(c => c[0] === '/agent-session/stop')
    .map(c => JSON.parse((c[1] as { body: string }).body))

  test('two running conversations: two stops, before the row is deleted', async () => {
    h.runningChats.mockResolvedValue([
      { userId: 'u1', sessionId: 'session_a' }, { userId: 'u1', sessionId: 'session_b' },
    ])
    expect((await DELETE(del(), params('p1'))).status).toBe(200)
    expect(h.runningChats).toHaveBeenCalledWith({
      where: { projectId: 'p1', agentRunning: true }, select: { userId: true, sessionId: true },
    })
    expect(stopBodies()).toEqual([
      { user_id: 'u1', project_id: 'p1', session_id: 'session_a' },
      { user_id: 'u1', project_id: 'p1', session_id: 'session_b' },
    ])
    expect(h.agentFetch.mock.invocationCallOrder[1]).toBeLessThan(h.projectDelete.mock.invocationCallOrder[0])
  })

  test('a failing stop is logged and the delete still succeeds', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    h.runningChats.mockResolvedValue([{ userId: 'u1', sessionId: 'session_a' }, { userId: 'u1', sessionId: 'session_b' }])
    h.agentFetch.mockImplementation(async (path: string, init: { body?: string }) => {
      if (path !== '/agent-session/stop') return { ok: true, status: 200 }
      if (String(init.body).includes('session_a')) throw new Error('agent down')
      return { ok: false, status: 503 }
    })
    expect((await DELETE(del(), params('p1'))).status).toBe(200)
    expect(h.projectDelete).toHaveBeenCalled()
    expect(warn.mock.calls.filter(c => String(c[0]).includes('before project delete'))).toHaveLength(2)
    warn.mockRestore()
  })

  test('no running conversation: no stop call', async () => {
    expect((await DELETE(del(), params('p1'))).status).toBe(200)
    expect(stopBodies()).toEqual([])
  })

  test('the read failing does not block the delete either', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    h.runningChats.mockRejectedValue(new Error('db'))
    expect((await DELETE(del(), params('p1'))).status).toBe(200)
    expect(h.projectDelete).toHaveBeenCalled()
  })
})
