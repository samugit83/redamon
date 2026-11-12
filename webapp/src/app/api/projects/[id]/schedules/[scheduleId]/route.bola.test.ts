/**
 * BOLA — PATCH/DELETE /api/projects/[id]/schedules/[scheduleId].
 *
 * The schedule id is client-supplied, so owning project A must not let a caller
 * retime, disable or delete project B's scheduled scans.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  requireEff: vi.fn(),
  requireProjectAccess: vi.fn(),
  findUnique: vi.fn(),
  update: vi.fn(),
  del: vi.fn(),
  findMany: vi.fn(),
  envelope: vi.fn(),
  audit: vi.fn(),
  findProject: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.requireEff(),
  requireProjectAccess: (...a: unknown[]) => h.requireProjectAccess(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    scanSchedule: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      update: (...a: unknown[]) => h.update(...a),
      delete: (...a: unknown[]) => h.del(...a),
      findMany: (...a: unknown[]) => h.findMany(...a),
    },
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/scanEnvelope', () => ({ fetchScanEnvelope: () => h.envelope() }))

import { PATCH, DELETE } from './route'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const params = (id: string, scheduleId: string) => ({ params: Promise.resolve({ id, scheduleId }) })
const patchReq = (body: unknown) => new NextRequest('http://x/api/projects/p1/schedules/s1', {
  method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
})
const delReq = () => new NextRequest('http://x/api/projects/p1/schedules/s1', { method: 'DELETE' })

const SCHEDULE = {
  id: 's1', projectId: 'p1', userId: 'owner', label: '', mode: 'interval',
  runAt: null, intervalMinutes: 1440, cronExpr: null, scanMode: 'new',
  enabled: true, nextRunAt: new Date(), estimatedEnvelopeBytes: null,
}

beforeEach(() => {
  vi.clearAllMocks()
  h.requireEff.mockResolvedValue({ userId: 'owner' })
  h.requireProjectAccess.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
  h.findUnique.mockResolvedValue(SCHEDULE)
  h.findMany.mockResolvedValue([])
  h.envelope.mockResolvedValue(null)
  h.update.mockImplementation(async ({ data }: { data: Record<string, unknown> }) =>
    ({ ...SCHEDULE, ...data }))
  h.del.mockResolvedValue({})
  h.findProject.mockResolvedValue({
    ipMode: false, domainBatchMode: false, domainBatchHosts: [], targetDomain: 'example.com', subdomainList: [],
  })
})

describe('PATCH — BOLA', () => {
  test("another user's project → 404, nothing written", async () => {
    h.requireProjectAccess.mockResolvedValue(NOT_FOUND)
    expect((await PATCH(patchReq({ enabled: false }), params('victimProj', 's1'))).status).toBe(404)
    expect(h.update).not.toHaveBeenCalled()
  })

  test("EXPLOIT: a schedule id from another project → 404, nothing written", async () => {
    h.findUnique.mockResolvedValue({ ...SCHEDULE, projectId: 'someoneElse' })
    expect((await PATCH(patchReq({ enabled: false }), params('p1', 'sOther'))).status).toBe(404)
    expect(h.update).not.toHaveBeenCalled()
  })
})

describe('PATCH — behavior', () => {
  test('a bare enable/disable does not re-validate the timing', async () => {
    const res = await PATCH(patchReq({ enabled: false }), params('p1', 's1'))
    expect(res.status).toBe(200)
    expect(h.update).toHaveBeenCalledWith({ where: { id: 's1' }, data: { enabled: false } })
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({ action: 'scan-schedule.update' }))
  })

  test('a non-boolean enabled is rejected', async () => {
    expect((await PATCH(patchReq({ enabled: 'yes' }), params('p1', 's1'))).status).toBe(400)
    expect(h.update).not.toHaveBeenCalled()
  })

  test('a label-only edit does not re-validate the timing', async () => {
    // A spent one-off schedule has a runAt in the past. Re-validating it on every
    // PATCH made renaming (or re-enabling) it impossible: "runAt must be in the
    // future" for an edit that never touched the timing.
    h.findUnique.mockResolvedValue({
      ...SCHEDULE, mode: 'once', intervalMinutes: null,
      runAt: new Date('2020-01-01T00:00:00Z'), nextRunAt: null, enabled: false,
    })
    const res = await PATCH(patchReq({ label: 'last year’s baseline scan' }), params('p1', 's1'))
    expect(res.status).toBe(200)
    expect(h.update.mock.calls[0][0].data).toMatchObject({ label: 'last year’s baseline scan' })
    // Timing is untouched, so nextRunAt must not be recomputed.
    expect(h.update.mock.calls[0][0].data.nextRunAt).toBeUndefined()
  })

  test('a scanMode-only edit is likewise allowed on a spent schedule', async () => {
    h.findUnique.mockResolvedValue({
      ...SCHEDULE, mode: 'once', intervalMinutes: null,
      runAt: new Date('2020-01-01T00:00:00Z'), nextRunAt: null, enabled: false,
    })
    const res = await PATCH(patchReq({ scanMode: 'overwrite' }), params('p1', 's1'))
    expect(res.status).toBe(200)
    expect(h.update.mock.calls[0][0].data).toMatchObject({ scanMode: 'overwrite' })
  })

  test('an invalid scanMode is still rejected', async () => {
    const res = await PATCH(patchReq({ scanMode: 'nuke' }), params('p1', 's1'))
    expect(res.status).toBe(400)
    expect(h.update).not.toHaveBeenCalled()
  })

  test('a retime is validated and recomputes the next run', async () => {
    const res = await PATCH(patchReq({ mode: 'cron', cronExpr: '0 4 * * *' }), params('p1', 's1'))
    expect(res.status).toBe(200)
    const data = h.update.mock.calls[0][0].data
    expect(data.mode).toBe('cron')
    expect(data.cronExpr).toBe('0 4 * * *')
    expect(data.nextRunAt).toBeInstanceOf(Date)
  })

  test('an invalid retime is rejected without touching the row', async () => {
    expect((await PATCH(patchReq({ mode: 'cron', cronExpr: '* * * * *' }), params('p1', 's1'))).status).toBe(400)
    expect(h.update).not.toHaveBeenCalled()
  })

  test('a retime that would overload the RAM window is rejected', async () => {
    const MB = 1024 * 1024
    h.envelope.mockResolvedValue({ envelopeBytes: 5000 * MB, scanPoolBytes: 6000 * MB })
    h.findMany.mockResolvedValue([
      { id: 'other', nextRunAt: new Date(Date.now() + 30 * 60_000), estimatedEnvelopeBytes: BigInt(5000 * MB) },
    ])
    const res = await PATCH(patchReq({ mode: 'interval', intervalMinutes: 30 }), params('p1', 's1'))
    expect(res.status).toBe(409)
    expect(h.update).not.toHaveBeenCalled()
    // The schedule being edited must not be counted as its own conflict.
    expect(h.findMany.mock.calls[0][0].where.id).toEqual({ not: 's1' })
  })
})

describe('DELETE', () => {
  test("EXPLOIT: a schedule id from another project → 404, nothing deleted", async () => {
    h.findUnique.mockResolvedValue({ ...SCHEDULE, projectId: 'someoneElse' })
    expect((await DELETE(delReq(), params('p1', 'sOther'))).status).toBe(404)
    expect(h.del).not.toHaveBeenCalled()
  })

  test('owner → deletes and audits', async () => {
    const res = await DELETE(delReq(), params('p1', 's1'))
    expect(res.status).toBe(200)
    expect(h.del).toHaveBeenCalledWith({ where: { id: 's1' } })
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({ action: 'scan-schedule.delete' }))
  })
})

// WEB-31: a schedule paused because its saved scope is no longer valid stays
// paused until the scope is fixed.
describe('PATCH — re-enabling against an invalid saved scope', () => {
  const PAUSED = { ...SCHEDULE, enabled: false }

  test('enabling is refused with 422 while the scope holds a refused entry, naming it', async () => {
    h.findUnique.mockResolvedValue(PAUSED)
    h.findProject.mockResolvedValue({
      ipMode: false, domainBatchMode: true, domainBatchHosts: ['*.com.vn', 'www.example.com'],
      targetDomain: '', subdomainList: [],
    })
    const res = await PATCH(patchReq({ enabled: true }), params('p1', 's1'))
    expect(res.status).toBe(422)
    const body = await res.json()
    expect(body.code).toBe('scope_invalid')
    expect(body.error).toContain('*.com.vn')
    expect(h.update).not.toHaveBeenCalled()
  })

  test('a retime that turns it on is refused too', async () => {
    h.findUnique.mockResolvedValue(PAUSED)
    h.findProject.mockResolvedValue({
      ipMode: false, domainBatchMode: false, domainBatchHosts: [], targetDomain: 'co.uk', subdomainList: [],
    })
    expect((await PATCH(patchReq({ enabled: true, intervalMinutes: 60 }), params('p1', 's1'))).status).toBe(422)
    expect(h.update).not.toHaveBeenCalled()
  })

  test('disabling, renaming and enabling a valid scope are unaffected', async () => {
    h.findUnique.mockResolvedValue(PAUSED)
    expect((await PATCH(patchReq({ enabled: true }), params('p1', 's1'))).status).toBe(200)
    h.findProject.mockResolvedValue({
      ipMode: false, domainBatchMode: false, domainBatchHosts: [], targetDomain: 'co.uk', subdomainList: [],
    })
    expect((await PATCH(patchReq({ enabled: false }), params('p1', 's1'))).status).toBe(200)
    expect((await PATCH(patchReq({ label: 'nightly' }), params('p1', 's1'))).status).toBe(200)
  })
})
