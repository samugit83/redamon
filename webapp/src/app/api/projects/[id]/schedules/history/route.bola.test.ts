/**
 * BOLA + scoping — DELETE /api/projects/[id]/schedules/history.
 *
 * Clearing run history must prove project ownership before it deletes anything,
 * and every delete must be scoped to the project so a body-supplied id can never
 * remove another project's rows.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  requireEff: vi.fn(),
  requireProjectAccess: vi.fn(),
  deleteMany: vi.fn(),
  queueDeleteMany: vi.fn(),
  audit: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.requireEff(),
  requireProjectAccess: (...a: unknown[]) => h.requireProjectAccess(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    scanJob: { deleteMany: (...a: unknown[]) => h.deleteMany(...a) },
    jobQueue: { deleteMany: (...a: unknown[]) => h.queueDeleteMany(...a) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { DELETE } from './route'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const UNAUTH = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const del = (body?: unknown) =>
  new NextRequest('http://x/api/projects/p1/schedules/history', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })

beforeEach(() => {
  vi.clearAllMocks()
  h.requireEff.mockResolvedValue({ userId: 'owner' })
  h.requireProjectAccess.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
  h.deleteMany.mockResolvedValue({ count: 3 })
  h.queueDeleteMany.mockResolvedValue({ count: 0 })
})

describe('DELETE — BOLA', () => {
  test('no session → 401 before any delete', async () => {
    h.requireEff.mockResolvedValue(UNAUTH)
    expect((await DELETE(del({}), params('p1'))).status).toBe(401)
    expect(h.deleteMany).not.toHaveBeenCalled()
  })

  test("EXPLOIT: clearing another user's history → 404, nothing deleted", async () => {
    h.requireProjectAccess.mockResolvedValue(NOT_FOUND)
    expect((await DELETE(del({}), params('victimProj'))).status).toBe(404)
    expect(h.deleteMany).not.toHaveBeenCalled()
  })
})

describe('DELETE — scoping', () => {
  test('selected ids are scoped to THIS project (a foreign id cannot escape the where)', async () => {
    await DELETE(del({ ids: ['j1', 'j2', 'foreign-from-another-project'] }), params('p1'))
    expect(h.deleteMany).toHaveBeenCalledWith({
      where: { projectId: 'p1', id: { in: ['j1', 'j2', 'foreign-from-another-project'] } },
    })
  })

  test('no ids → clears the whole project history (still project-scoped)', async () => {
    await DELETE(del({}), params('p1'))
    expect(h.deleteMany).toHaveBeenCalledWith({ where: { projectId: 'p1' } })
  })

  test('an empty id list is treated as "clear all", not "delete nothing"', async () => {
    await DELETE(del({ ids: [] }), params('p1'))
    expect(h.deleteMany).toHaveBeenCalledWith({ where: { projectId: 'p1' } })
  })

  test('non-string ids are filtered out before the query', async () => {
    await DELETE(del({ ids: ['ok', 42, null, { a: 1 }] }), params('p1'))
    expect(h.deleteMany).toHaveBeenCalledWith({ where: { projectId: 'p1', id: { in: ['ok'] } } })
  })

  test('reports the deleted count and audits the clear', async () => {
    const res = await DELETE(del({ ids: ['j1'] }), params('p1'))
    expect((await res.json()).deleted).toBe(3)
    expect(h.audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'scan-job.history-clear', targetId: 'p1' })
    )
  })

  // The history table also lists finished queue jobs (the only record a
  // non-full-recon run leaves), so their ids arrive here too.
  test('deletes terminal queue rows as well, and counts them', async () => {
    h.queueDeleteMany.mockResolvedValue({ count: 2 })
    const res = await DELETE(del({ ids: ['j1', 'q1', 'q2'] }), params('p1'))
    expect((await res.json()).deleted).toBe(5)
    expect(h.queueDeleteMany).toHaveBeenCalledWith({
      where: {
        projectId: 'p1',
        id: { in: ['j1', 'q1', 'q2'] },
        status: { in: ['done', 'failed', 'canceled'] },
      },
    })
  })

  test('never deletes a queued or running job through the history endpoint', async () => {
    await DELETE(del({}), params('p1'))
    const where = h.queueDeleteMany.mock.calls[0][0].where
    expect(where.status).toEqual({ in: ['done', 'failed', 'canceled'] })
    expect(where.projectId).toBe('p1')
  })
})
