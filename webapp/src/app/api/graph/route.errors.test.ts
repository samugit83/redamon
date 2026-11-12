/**
 * /api/graph failures answer a fixed sentence and a code (G-9, P-10, G-53).
 *
 * Both handlers used to answer `error.message`: a Neo4j error quotes the Cypher
 * and its values, so target data reached the screen, while the canvas showed
 * only "Failed to fetch graph data" without the status.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ read: vi.fn(), run: vi.fn(), eff: vi.fn() }))

vi.mock('./liveRead', () => ({ readLiveGraph: (...a: unknown[]) => h.read(...a) }))
vi.mock('./cache', () => ({ getCached: () => null, setCached: () => 'e', invalidateCache: vi.fn() }))
vi.mock('./neo4j', () => ({ getGraphSession: () => ({ run: (...a: unknown[]) => h.run(...a), close: vi.fn() }) }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.eff(),
  requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'owner' } }),
}))

import { GET, DELETE } from './route'

const LEAK = "MATCH (s:Subdomain {name: 'admin.target.example'})"

beforeEach(() => {
  vi.clearAllMocks()
  h.eff.mockResolvedValue({ userId: 'owner' })
})

describe('/api/graph failures', () => {
  test('a dropped database is ServiceUnavailable, never the message', async () => {
    h.read.mockRejectedValue(Object.assign(new Error(`${LEAK} failed`), { name: 'Neo4jError', code: 'ServiceUnavailable' }))
    const res = await GET(new NextRequest('http://x/api/graph?projectId=p1'))
    expect(res.status).toBe(500)
    const text = await res.text()
    expect(JSON.parse(text)).toEqual({ error: 'The graph query failed', code: 'ServiceUnavailable' })
    expect(text).not.toContain('admin.target.example')
  })

  test('a server error keeps its Neo.* status code', async () => {
    h.read.mockRejectedValue(Object.assign(new Error(LEAK), { code: 'Neo.TransientError.Transaction.DeadlockDetected' }))
    const res = await GET(new NextRequest('http://x/api/graph?projectId=p1'))
    expect((await res.json()).code).toBe('Neo.TransientError.Transaction.DeadlockDetected')
  })

  test('a failure in the ownership check is a readable 500, not an empty one', async () => {
    h.eff.mockRejectedValue(Object.assign(new Error('db'), { code: 'P1001' }))
    const res = await GET(new NextRequest('http://x/api/graph?projectId=p1'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'The graph could not be loaded', code: 'P1001' })
  })

  test('a failed node delete answers a code, not the Cypher', async () => {
    h.run.mockRejectedValue(Object.assign(new Error(LEAK), { code: 'Neo.ClientError.Schema.ConstraintValidationFailed' }))
    const res = await DELETE(new NextRequest('http://x/api/graph?nodeId=7&projectId=p1', { method: 'DELETE' }))
    expect(res.status).toBe(500)
    const text = await res.text()
    expect(JSON.parse(text)).toEqual({ error: 'Delete failed', code: 'Neo.ClientError.Schema.ConstraintValidationFailed' })
    expect(text).not.toContain('admin.target.example')
  })
})
