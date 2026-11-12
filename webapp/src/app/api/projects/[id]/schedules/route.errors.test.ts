/**
 * The schedule routes answer a failure with a fixed sentence and a code. Several
 * Prisma reads and writes sat outside their try/catch (the project read, the
 * non-timing PATCH), so a database error there was Next's empty 500, which the
 * Scans tab could only show as nothing at all.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  findSchedule: vi.fn(),
  findSchedules: vi.fn(),
  update: vi.fn(),
  del: vi.fn(),
  findProject: vi.fn(),
  findJobs: vi.fn(),
  findQueue: vi.fn(),
  deleteJobs: vi.fn(),
  deleteQueue: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: async () => ({ userId: 'owner' }),
  requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'owner' } }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    scanSchedule: {
      findUnique: (...a: unknown[]) => h.findSchedule(...a),
      findMany: (...a: unknown[]) => h.findSchedules(...a),
      update: (...a: unknown[]) => h.update(...a),
      delete: (...a: unknown[]) => h.del(...a),
    },
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    scanJob: { findMany: (...a: unknown[]) => h.findJobs(...a), deleteMany: (...a: unknown[]) => h.deleteJobs(...a) },
    jobQueue: { findMany: (...a: unknown[]) => h.findQueue(...a), deleteMany: (...a: unknown[]) => h.deleteQueue(...a) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/scanEnvelope', () => ({ fetchScanEnvelope: async () => null }))

import { GET as list, POST as create } from './route'
import { PATCH as patch, DELETE as remove } from './[scheduleId]/route'
import { DELETE as clearHistory } from './history/route'

const withCode = (message: string, code: string) => Object.assign(new Error(message), { code })
const project = { params: Promise.resolve({ id: 'p1' }) }
const schedule = { params: Promise.resolve({ id: 'p1', scheduleId: 's1' }) }
const body = (method: string, payload: unknown) => new NextRequest('http://x/api/projects/p1/schedules', {
  method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
})
const SCHEDULE = {
  id: 's1', projectId: 'p1', label: '', mode: 'interval', runAt: null, intervalMinutes: 1440,
  cronExpr: null, scanMode: 'new', enabled: false, nextRunAt: null, estimatedEnvelopeBytes: null,
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.findSchedule.mockResolvedValue(SCHEDULE)
})

describe('schedule routes', () => {
  test('a failed list answers its code, not the query text', async () => {
    h.findSchedules.mockRejectedValue(withCode('Timed out fetching a new connection from the pool', 'P2024'))
    h.findJobs.mockResolvedValue([])
    h.findQueue.mockResolvedValue([])
    const res = await list(new NextRequest('http://x'), project)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to list schedules', code: 'P2024' })
  })

  test('a project read that fails before the try is readable, not an empty 500', async () => {
    h.findProject.mockRejectedValue(withCode("Can't reach database server at db:5432", 'P1001'))
    const res = await create(body('POST', { mode: 'interval', intervalMinutes: 60, enabled: true }), project)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to create the schedule', code: 'P1001' })
  })

  test('a toggle whose write fails is readable too (that write had no try at all)', async () => {
    h.update.mockRejectedValue(withCode('Transaction failed due to a write conflict', 'P2034'))
    const res = await patch(body('PATCH', { label: 'nightly' }), schedule)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to update the schedule', code: 'P2034' })
  })

  test('a failed delete and a failed history clear answer their codes', async () => {
    h.del.mockRejectedValue(withCode('Record to delete does not exist.', 'P2025'))
    expect(await (await remove(new NextRequest('http://x', { method: 'DELETE' }), schedule)).json())
      .toEqual({ error: 'Failed to delete the schedule', code: 'P2025' })

    h.deleteJobs.mockRejectedValue(withCode('deadlock detected', 'P2034'))
    h.deleteQueue.mockResolvedValue({ count: 0 })
    expect(await (await clearHistory(body('DELETE', {}), project)).json())
      .toEqual({ error: 'Failed to clear run history', code: 'P2034' })
  })
})
