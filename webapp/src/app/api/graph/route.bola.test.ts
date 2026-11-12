/**
 * BOLA exploit-repro — GET/DELETE /api/graph.
 *
 * Before the fix, /api/graph?projectId=P returned the full subgraph filtered only
 * by project_id, with NO ownership check — any user (or an admin simulating someone
 * else) read another user's graph by pasting a projectId. Fix: requireProjectAccess
 * before any Neo4j session is opened.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGetGraphSession = vi.fn()
const mockRequireEff = vi.fn()
const mockRequireProjectAccess = vi.fn()

vi.mock('./neo4j', () => ({ getGraphSession: () => mockGetGraphSession() }))
vi.mock('./format', () => ({ formatGraphRecords: () => ({ nodes: [], edges: [] }) }))
vi.mock('./cache', () => ({ getCached: () => null, setCached: vi.fn(), invalidateCache: vi.fn() }))
vi.mock('@/lib/prisma', () => ({
  default: { conversation: { findMany: vi.fn().mockResolvedValue([]) } },
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => mockRequireEff(),
  requireProjectAccess: (...a: unknown[]) => mockRequireProjectAccess(...a),
}))

import { GET, DELETE } from './route'

const FORBIDDEN = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
const UNAUTH = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

beforeEach(() => {
  vi.clearAllMocks()
  mockGetGraphSession.mockReturnValue({ run: vi.fn().mockResolvedValue({ records: [] }), close: vi.fn() })
})

describe('GET /api/graph — BOLA', () => {
  test('EXPLOIT: cross-user projectId → 403 BEFORE any Neo4j session opens', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'attacker' })
    mockRequireProjectAccess.mockResolvedValue(FORBIDDEN)
    const res = await GET(new NextRequest('http://x/api/graph?projectId=victimProj'))
    expect(res.status).toBe(403)
    expect(mockGetGraphSession).not.toHaveBeenCalled()
  })

  test('no session → 401, project access not even checked', async () => {
    mockRequireEff.mockResolvedValue(UNAUTH)
    const res = await GET(new NextRequest('http://x/api/graph?projectId=p'))
    expect(res.status).toBe(401)
    expect(mockRequireProjectAccess).not.toHaveBeenCalled()
    expect(mockGetGraphSession).not.toHaveBeenCalled()
  })

  test('owner → guard passes, proceeds to open a graph session', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'victim' })
    mockRequireProjectAccess.mockResolvedValue({ project: { id: 'p', userId: 'victim' } })
    await GET(new NextRequest('http://x/api/graph?projectId=p'))
    expect(mockGetGraphSession).toHaveBeenCalled()
  })

  test('missing projectId → 400 (no auth work)', async () => {
    const res = await GET(new NextRequest('http://x/api/graph'))
    expect(res.status).toBe(400)
  })
})

describe('DELETE /api/graph — BOLA', () => {
  test('EXPLOIT: cross-user node delete → 403 before session opens', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'attacker' })
    mockRequireProjectAccess.mockResolvedValue(FORBIDDEN)
    const res = await DELETE(new NextRequest('http://x/api/graph?nodeId=5&projectId=victimProj', { method: 'DELETE' }))
    expect(res.status).toBe(403)
    expect(mockGetGraphSession).not.toHaveBeenCalled()
  })
})
