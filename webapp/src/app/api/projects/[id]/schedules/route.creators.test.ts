/**
 * GET /api/projects/[id]/schedules names people (step 4.7, SH-24 display): on a shared project the
 * reader is not always who created a schedule or started a run, so each schedule carries `createdBy`
 * and each run `startedBy` (a ScanJob's initiator, a queue row's enqueuer), as `{name, email}` read
 * in one query for every row; a run that records nobody, or an account gone since, is null.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  schedules: [] as unknown[], jobs: [] as unknown[], queue: [] as unknown[],
  users: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: async () => ({ userId: 'carol' }),
  requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'alice' } }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    scanSchedule: { findMany: async () => h.schedules },
    scanJob: { findMany: async () => h.jobs },
    jobQueue: { findMany: async () => h.queue },
    user: { findMany: (...a: unknown[]) => h.users(...a) },
  },
}))

import { GET } from './route'

const get = () => GET(new NextRequest('http://x/api/projects/p1/schedules'), { params: Promise.resolve({ id: 'p1' }) })

beforeEach(() => {
  h.schedules = []
  h.jobs = []
  h.queue = []
  h.users.mockReset()
  h.users.mockResolvedValue([
    { id: 'alice', name: 'Alice Owner', email: 'alice@e2e.local' },
    { id: 'carol', name: 'Carol', email: 'carol@e2e.local' },
  ])
})

describe('who created and who started', () => {
  test('a schedule names its creator, a run its starter, the queue row its enqueuer; one query for all', async () => {
    h.schedules = [{ id: 's1', projectId: 'p1', userId: 'alice', estimatedEnvelopeBytes: null }]
    h.jobs = [
      { id: 'j1', kind: 'full_recon', trigger: 'manual', mode: 'new', status: 'completed', startedAt: null, finishedAt: null,
        createdAt: new Date('2026-11-10T10:00:00Z'), nodeCount: 1, ramReason: null, scheduleId: null, version: null, initiatedByUserId: 'carol' },
      { id: 'j0', kind: 'full_recon', trigger: 'scheduled', mode: 'new', status: 'completed', startedAt: null, finishedAt: null,
        createdAt: new Date('2026-11-09T10:00:00Z'), nodeCount: 1, ramReason: null, scheduleId: 's1', version: null, initiatedByUserId: null },
    ]
    h.queue = [{ id: 'q1', kind: 'gvm', status: 'done', error: '', blockedReason: '', enqueuedAt: new Date('2026-11-11T10:00:00Z'),
      startedAt: null, finishedAt: null, scheduleId: null, userId: 'alice' }]
    const res = await get()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.schedules[0].createdBy).toEqual({ name: 'Alice Owner', email: 'alice@e2e.local' })
    expect(body.jobs.map((j: { id: string; startedBy: unknown }) => [j.id, j.startedBy])).toEqual([
      ['q1', { name: 'Alice Owner', email: 'alice@e2e.local' }],
      ['j1', { name: 'Carol', email: 'carol@e2e.local' }],
      ['j0', null],
    ])
    expect(h.users).toHaveBeenCalledTimes(1)
    const where = h.users.mock.calls[0][0] as { where: { id: { in: string[] } }; select: Record<string, boolean> }
    expect([...where.where.id.in].sort()).toEqual(['alice', 'carol'])
    expect(where.select).toEqual({ id: true, name: true, email: true })
  })

  test('an account gone since reads as null; no row naming anyone reads no account', async () => {
    h.schedules = [{ id: 's1', projectId: 'p1', userId: 'gone', estimatedEnvelopeBytes: null }]
    expect((await (await get()).json()).schedules[0].createdBy).toBeNull()
    h.users.mockClear()
    h.schedules = []
    await get()
    expect(h.users).not.toHaveBeenCalled()
  })
})
