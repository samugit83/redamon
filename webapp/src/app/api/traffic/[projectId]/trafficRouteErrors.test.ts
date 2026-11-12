/**
 * Traffic routes on a DB or body-store failure: a fixed sentence plus the Prisma
 * code or errno, never the raw message (it can quote a filter value, a host or a
 * captured body path).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/traffic/[projectId]/trafficRouteErrors.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

const { db, readBody } = vi.hoisted(() => ({
  db: {
    capturedHttpTransaction: {
      findMany: vi.fn(),
      count: vi.fn(),
      findFirst: vi.fn(),
      deleteMany: vi.fn(),
    },
  },
  readBody: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({ default: db }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1' }),
  requireProjectAccess: vi.fn().mockResolvedValue({ project: { id: 'p1', userId: 'u1' } }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))
vi.mock('@/lib/captureBodies', () => ({
  gcOrphanBodies: vi.fn().mockResolvedValue({ deleted: 0 }),
  readCapturedBody: (...a: unknown[]) => readBody(...a),
}))

import { GET as LIST, DELETE } from './route'
import { GET as DETAIL } from './[id]/route'
import { GET as FACETS } from './facets/route'

const params = { params: Promise.resolve({ projectId: 'p1' }) }
const P2024 = () => Object.assign(new Error('Timed out fetching a new connection; host=secret.target.example'), { code: 'P2024' })

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('traffic routes answer {error, code}', () => {
  test('list: a statement timeout on the body search keeps the fixed message and adds the Prisma code', async () => {
    db.capturedHttpTransaction.findMany.mockRejectedValue(P2024())
    db.capturedHttpTransaction.count.mockResolvedValue(0)
    const res = await LIST(new NextRequest('http://x/api/traffic/p1?bodyq=secret.target.example'), params)
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to list traffic', code: 'P2024' })
    expect(JSON.stringify(body)).not.toContain('target.example')
  })

  test('delete: the Prisma code reaches the client', async () => {
    db.capturedHttpTransaction.findMany.mockRejectedValue(P2024())
    const res = await DELETE(new NextRequest('http://x', { method: 'DELETE', body: JSON.stringify({ ids: ['a'] }) }), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to delete traffic', code: 'P2024' })
  })

  test('detail: a body-store read failure carries the errno', async () => {
    db.capturedHttpTransaction.findFirst.mockResolvedValue({ id: 't1', reqBody: null, reqBodyRef: 'abc', respBody: 'x', respBodyRef: null })
    readBody.mockRejectedValue(Object.assign(new Error("ENOENT: no such file '/data/bodies/abc'"), { code: 'ENOENT' }))
    const res = await DETAIL(new NextRequest('http://x'), { params: Promise.resolve({ projectId: 'p1', id: 't1' }) })
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to load transaction', code: 'ENOENT' })
  })

  test('facets: the Prisma code reaches the client', async () => {
    db.capturedHttpTransaction.findMany.mockRejectedValue(P2024())
    const res = await FACETS(new NextRequest('http://x'), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to load facets', code: 'P2024' })
  })
})
