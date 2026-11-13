/**
 * Deleting a conversation removes its attack chain from the project owner's graph (step 5.3, SH-33).
 *
 * The agent writes a run's chain under the project's owner, the graph tenant, whoever ran it,
 * so a collaborator's conversation names them while its chain names the owner. The DELETE stops
 * the run by its author (the agent keys a run on its person, `sub:pid:sid`) and deletes the chain
 * under the owner the guard's project check read, scoped to the project and the session.
 *
 * Guard, conversation guard, Prisma, the agent and Neo4j are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  author: 'collab-1',
  owner: 'owner-1',
  agentFetch: vi.fn(),
  neo4jRun: vi.fn(),
  requirePermission: vi.fn(),
  deleted: vi.fn(),
}))

vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: (...a: unknown[]) => h.requirePermission(...a),
}))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: async () => ({ userId: h.author }),
  requireConversationAccess: async () => ({ conversation: { id: 'c1', userId: h.author, projectId: 'p1' } }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    conversation: {
      findUnique: async () => ({ sessionId: 's1', userId: h.author, projectId: 'p1' }),
      delete: (...a: unknown[]) => h.deleted(...a),
    },
  },
}))
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: (...a: unknown[]) => h.agentFetch(...a),
  AgentUnreachableError: class extends Error {},
}))
vi.mock('../../graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => h.neo4jRun(...a), close: async () => {} }),
}))

import { DELETE } from './route'

const del = () => DELETE(new NextRequest('http://x/api/conversations/c1', { method: 'DELETE' }), { params: Promise.resolve({ id: 'c1' }) })

beforeEach(() => {
  h.author = 'collab-1'
  h.owner = 'owner-1'
  h.agentFetch.mockReset().mockResolvedValue(new Response('{"stopped":true}', { status: 200 }))
  h.neo4jRun.mockReset().mockResolvedValue({ records: [] })
  h.deleted.mockReset().mockResolvedValue({})
  h.requirePermission.mockReset().mockImplementation(async () => ({
    effective: { userId: h.author },
    access: { project: { id: 'p1', userId: h.owner }, level: 'owner', toggles: { rawData: true }, via: 'owner' },
  }))
})

describe('a collaborator deletes their conversation on a shared project', () => {
  test('the run is stopped by its author and the chain deleted under the owner', async () => {
    const res = await del()
    expect(await res.json()).toEqual({ success: true })
    expect(h.requirePermission).toHaveBeenCalledWith(expect.anything(), 'agent:chat', { projectId: 'p1' })
    const [path, init] = h.agentFetch.mock.calls[0]
    expect(path).toBe('/agent-session/stop')
    expect(JSON.parse(init.body)).toEqual({ user_id: 'collab-1', project_id: 'p1', session_id: 's1' })
    const [cypher, params] = h.neo4jRun.mock.calls[0]
    expect(params).toEqual({ chainId: 's1', userId: 'owner-1', projectId: 'p1' })
    expect(cypher).toContain('n.chain_id = $chainId')
    expect(cypher).toContain('n.project_id = $projectId')
    expect(h.deleted).toHaveBeenCalledWith({ where: { id: 'c1' } })
  })

  test('the owner deleting their own conversation: both name the owner, as before', async () => {
    h.author = 'owner-1'
    await del()
    expect(JSON.parse(h.agentFetch.mock.calls[0][1].body).user_id).toBe('owner-1')
    expect(h.neo4jRun.mock.calls[0][1].userId).toBe('owner-1')
  })
})
