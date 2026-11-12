/**
 * BOLA exploit-repro — GET /api/projects/[id]/export.
 *
 * The export bundles the ENTIRE project (row + RoE binary, conversations, messages,
 * reports, Neo4j subgraph, presets). Before the fix it had NO ownership check — any
 * logged-in user could download another user's whole project. Fix: requireProjectAccess
 * before any data is read.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockProjectFindUnique = vi.fn()
const mockRequireEff = vi.fn()
const mockRequireProjectAccess = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => mockProjectFindUnique(...a) },
    conversation: { findMany: vi.fn().mockResolvedValue([]) },
    report: { findMany: vi.fn().mockResolvedValue([]) },
    userProjectPreset: { findMany: vi.fn().mockResolvedValue([]) },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn().mockResolvedValue({ records: [] }), close: vi.fn() }) }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => mockRequireEff(),
  requireProjectAccess: (...a: unknown[]) => mockRequireProjectAccess(...a),
}))

import { GET } from './route'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  mockProjectFindUnique.mockResolvedValue({ id: 'victimProj', userId: 'victim', name: 'secret', targetDomain: 'v.tld' })
})

describe('GET /api/projects/[id]/export — BOLA', () => {
  test('EXPLOIT: cross-user export → 404, project never read', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'attacker' })
    mockRequireProjectAccess.mockResolvedValue(NOT_FOUND)
    const res = await GET(new NextRequest('http://x/api/projects/victimProj/export'), params('victimProj'))
    expect(res.status).toBe(404)
    expect(mockProjectFindUnique).not.toHaveBeenCalled()
  })

  test('no session → 401, project access not checked', async () => {
    mockRequireEff.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    const res = await GET(new NextRequest('http://x/api/projects/victimProj/export'), params('victimProj'))
    expect(res.status).toBe(401)
    expect(mockRequireProjectAccess).not.toHaveBeenCalled()
  })

  test('owner → guard passes, proceeds to read the project', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'victim' })
    mockRequireProjectAccess.mockResolvedValue({ project: { id: 'victimProj', userId: 'victim' } })
    await GET(new NextRequest('http://x/api/projects/victimProj/export'), params('victimProj'))
    expect(mockProjectFindUnique).toHaveBeenCalled()
  })
})

describe('GET /api/projects/[id]/export — failures', () => {
  test('an export that fails answers a code, never the exception text', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockRequireEff.mockResolvedValue({ userId: 'victim' })
    mockRequireProjectAccess.mockResolvedValue({ project: { id: 'victimProj', userId: 'victim' } })
    mockProjectFindUnique.mockRejectedValue(Object.assign(
      new Error('Timed out fetching a new connection: SELECT * FROM "Project" WHERE "targetDomain" = \'v.tld\''),
      { code: 'P2024', name: 'PrismaClientKnownRequestError' },
    ))
    const res = await GET(new NextRequest('http://x/api/projects/victimProj/export'), params('victimProj'))
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Export failed', code: 'P2024' })
    expect(JSON.stringify(body)).not.toContain('v.tld')
  })
})
