/**
 * The purge stops an orphan chain's run by project and session (step 5.3).
 *
 * An attack chain names the project's owner, the graph tenant, whoever ran it, so its `user_id`
 * no longer builds the agent's session key (`sub:pid:sid`, the person's). The stop sends no user:
 * the agent stops that project's session whoever runs it. Session ids are unique.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ neo4jRun: vi.fn(), findMany: vi.fn() }))

vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: async () => ({
    effective: { userId: 'collab-1' },
    access: { project: { id: 'p1', userId: 'owner-1' }, level: 'owner', toggles: { rawData: true }, via: 'owner' },
  }),
}))
vi.mock('@/lib/prisma', () => ({ default: { conversation: { findMany: (...a: unknown[]) => h.findMany(...a) } } }))
vi.mock('../../../graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => h.neo4jRun(...a), close: async () => {} }),
}))

import { POST } from './route'

const orphan = (chainId: string) => ({ get: (k: string) => ({ chainId, userId: 'owner-1' } as Record<string, string>)[k] })

beforeEach(() => {
  vi.stubEnv('INTERNAL_API_KEY', 'test-master-key')
  h.findMany.mockReset().mockResolvedValue([{ sessionId: 'kept' }])
  h.neo4jRun.mockReset()
    .mockResolvedValueOnce({ records: [orphan('orphan-1'), orphan('kept')] })
    .mockResolvedValue({ records: [] })
})
afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe('POST purge-orphan-chains on a shared project', () => {
  test('each orphan is stopped by project and session, with no user, and only orphans are purged', async () => {
    const fetchMock = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response('{"stopped":true}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    const res = await POST(new NextRequest('http://x/api/projects/p1/purge-orphan-chains', { method: 'POST' }), { params: Promise.resolve({ id: 'p1' }) })
    expect(await res.json()).toEqual({ purged: 1, stopped: ['orphan-1'] })
    const stops = fetchMock.mock.calls.filter(c => String(c[0]).endsWith('/agent-session/stop'))
    expect(stops.map(c => JSON.parse(String(c[1]?.body)))).toEqual([{ project_id: 'p1', session_id: 'orphan-1' }])
    const deletes = h.neo4jRun.mock.calls.slice(1).map(c => c[1])
    expect(deletes).toEqual([{ chainId: 'orphan-1', projectId: 'p1' }])
  })
})
