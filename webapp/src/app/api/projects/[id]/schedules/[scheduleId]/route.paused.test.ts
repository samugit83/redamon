/**
 * PATCH /api/projects/[id]/schedules/[scheduleId] on a schedule that paused itself because the
 * person it runs as lost access to the project (step 5.5, D-13, `pausedReason`): turning it back on
 * here would run it again as that person, so it is refused (409 `schedule_paused`) and nothing is
 * written; the confirmation route makes the person confirming its actor instead. Everything else a
 * PATCH does (turning it off, renaming it, retiming it without turning it on) still works, and a
 * schedule a person turned off is re-enabled as before.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  requireEff: vi.fn(),
  requireProjectAccess: vi.fn(),
  findUnique: vi.fn(),
  update: vi.fn(),
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
      findMany: (...a: unknown[]) => h.findMany(...a),
    },
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/scanEnvelope', () => ({ fetchScanEnvelope: () => h.envelope() }))

import { PATCH } from './route'

const params = { params: Promise.resolve({ id: 'p1', scheduleId: 's1' }) }
const patch = (body: unknown) => PATCH(new NextRequest('http://x/api/projects/p1/schedules/s1', {
  method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}), params)

const PAUSED = {
  id: 's1', projectId: 'p1', userId: 'collab-1', label: 'nightly', mode: 'interval',
  runAt: null, intervalMinutes: 1440, cronExpr: null, scanMode: 'new',
  enabled: false, pausedReason: 'actor_no_access', nextRunAt: null, estimatedEnvelopeBytes: null,
}

beforeEach(() => {
  vi.clearAllMocks()
  h.requireEff.mockResolvedValue({ userId: 'owner' })
  h.requireProjectAccess.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
  h.findUnique.mockResolvedValue(PAUSED)
  h.findMany.mockResolvedValue([])
  h.envelope.mockResolvedValue(null)
  h.update.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...PAUSED, ...data }))
  h.findProject.mockResolvedValue({
    ipMode: false, domainBatchMode: false, domainBatchHosts: [], targetDomain: 'example.com', subdomainList: [],
  })
})

describe('a schedule paused because its actor lost access', () => {
  test('a plain re-enable is refused (409 schedule_paused): confirm it instead; nothing written', async () => {
    const res = await patch({ enabled: true })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'schedule_paused', pausedReason: 'actor_no_access' })
    expect(h.update).not.toHaveBeenCalled()
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('a retime that would turn it on is refused too', async () => {
    const res = await patch({ mode: 'interval', intervalMinutes: 60, enabled: true })
    expect(res.status).toBe(409)
    expect(h.update).not.toHaveBeenCalled()
  })

  test('renaming it, or turning it off, still works and keeps the reason', async () => {
    expect((await patch({ label: 'weekly' })).status).toBe(200)
    expect(h.update.mock.calls[0][0].data).toEqual({ label: 'weekly' })
    expect((await patch({ enabled: false })).status).toBe(200)
    expect(h.update.mock.calls[1][0].data).toEqual({ enabled: false })
  })

  test('a schedule a person turned off is re-enabled as before', async () => {
    h.findUnique.mockResolvedValue({ ...PAUSED, userId: 'owner', pausedReason: null })
    const res = await patch({ enabled: true })
    expect(res.status).toBe(200)
    expect(h.update.mock.calls[0][0].data).toEqual({ enabled: true })
  })
})
