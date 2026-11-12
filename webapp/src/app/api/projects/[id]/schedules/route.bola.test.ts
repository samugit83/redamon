/**
 * BOLA + validation — /api/projects/[id]/schedules.
 *
 * A schedule is a standing instruction to scan a target unattended, so creating
 * one on someone else's project would be both a BOLA and an abuse primitive. It
 * must therefore prove project ownership before anything is written, validate the
 * timing (scheduler-DoS guard), and honor the static RAM feasibility check.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  requireEff: vi.fn(),
  requireProjectAccess: vi.fn(),
  create: vi.fn(),
  findMany: vi.fn(),
  jobFindMany: vi.fn(),
  queueFindMany: vi.fn(),
  envelope: vi.fn(),
  audit: vi.fn(),
  projectFind: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.requireEff(),
  requireProjectAccess: (...a: unknown[]) => h.requireProjectAccess(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    scanSchedule: {
      create: (...a: unknown[]) => h.create(...a),
      findMany: (...a: unknown[]) => h.findMany(...a),
    },
    scanJob: { findMany: (...a: unknown[]) => h.jobFindMany(...a) },
    project: { findUnique: (...a: unknown[]) => h.projectFind(...a) },
    jobQueue: { findMany: (...a: unknown[]) => h.queueFindMany(...a) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/scanEnvelope', () => ({ fetchScanEnvelope: () => h.envelope() }))

import { GET, POST } from './route'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const UNAUTH = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const get = () => new NextRequest('http://x/api/projects/p1/schedules')
const post = (body: unknown) => new NextRequest('http://x/api/projects/p1/schedules', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
})
const MB = 1024 * 1024

beforeEach(() => {
  vi.clearAllMocks()
  h.requireEff.mockResolvedValue({ userId: 'owner' })
  h.requireProjectAccess.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
  h.findMany.mockResolvedValue([])
  h.jobFindMany.mockResolvedValue([])
  h.queueFindMany.mockResolvedValue([])
  h.envelope.mockResolvedValue({ envelopeBytes: 2000 * MB, scanPoolBytes: 8000 * MB })
  h.create.mockImplementation(async ({ data }: { data: Record<string, unknown> }) =>
    ({ id: 'sched1', ...data }))
  h.projectFind.mockResolvedValue({ ipMode: false, domainBatchMode: false, targetDomain: 'example.com', subdomainList: [] })
})

describe('GET — BOLA', () => {
  test('no session → 401 before any query', async () => {
    h.requireEff.mockResolvedValue(UNAUTH)
    expect((await GET(get(), params('p1'))).status).toBe(401)
    expect(h.findMany).not.toHaveBeenCalled()
  })

  test("another user's project → 404, no history leaked", async () => {
    h.requireProjectAccess.mockResolvedValue(NOT_FOUND)
    expect((await GET(get(), params('victimProj'))).status).toBe(404)
    expect(h.findMany).not.toHaveBeenCalled()
    expect(h.jobFindMany).not.toHaveBeenCalled()
    expect(h.queueFindMany).not.toHaveBeenCalled()
  })

  test('owner → schedules + run history, BigInt safely serialized', async () => {
    h.findMany.mockResolvedValue([
      { id: 's1', projectId: 'p1', mode: 'cron', estimatedEnvelopeBytes: BigInt(2000 * MB) },
    ])
    h.jobFindMany.mockResolvedValue([
      { id: 'j1', kind: 'full_recon', trigger: 'scheduled', mode: 'new', status: 'completed', startedAt: null,
        finishedAt: null, createdAt: new Date(), nodeCount: 5, ramReason: null,
        scheduleId: 's1', version: { seq: 2, label: 'Scan 2' } },
    ])
    const res = await GET(get(), params('p1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.schedules[0].estimatedEnvelopeBytes).toBe(2000 * MB)
    expect(body.jobs[0].version).toEqual({ seq: 2, label: 'Scan 2' })
    // Only full recon writes a ScanJob, so its rows are labelled as such.
    expect(body.jobs[0].kind).toBe('full_recon')
  })

  // Every non-full-recon run that finished is a JobQueue row; without them the
  // Type column would read 'Full recon' on every line forever.
  test('finished queue jobs join the run history, newest first, typed by kind', async () => {
    h.jobFindMany.mockResolvedValue([
      { id: 'j1', kind: 'full_recon', trigger: 'manual', mode: 'new', status: 'completed', startedAt: null,
        finishedAt: null, createdAt: new Date('2026-08-09T10:00:00Z'), nodeCount: 5,
        ramReason: null, scheduleId: null, version: null },
    ])
    h.queueFindMany.mockResolvedValue([
      { id: 'q1', kind: 'trufflehog', status: 'failed', error: 'exit 2', blockedReason: '',
        enqueuedAt: new Date('2026-08-09T12:00:00Z'), startedAt: null, finishedAt: null,
        scheduleId: null },
      { id: 'q2', kind: 'gvm', status: 'canceled', error: '', blockedReason: 'ram',
        enqueuedAt: new Date('2026-08-09T08:00:00Z'), startedAt: null, finishedAt: null,
        scheduleId: 'sched9' },
    ])
    const body = await (await GET(get(), params('p1'))).json()
    expect(body.jobs.map((j: { id: string }) => j.id)).toEqual(['q1', 'j1', 'q2'])
    expect(body.jobs[0]).toMatchObject({ kind: 'trufflehog', status: 'failed', ramReason: 'exit 2' })
    // A queue job carrying a scheduleId came from the scheduler.
    expect(body.jobs[2]).toMatchObject({ kind: 'gvm', status: 'canceled', trigger: 'scheduled' })
  })

  test('only terminal queue rows are pulled into the history', async () => {
    await GET(get(), params('p1'))
    expect(h.queueFindMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({
        projectId: 'p1',
        status: { in: ['done', 'failed', 'canceled'] },
        kind: { not: 'full_recon' },
      }),
    }))
  })

  // The ScanScheduleTable's "partial — N sources skipped" badge reads this field;
  // if the handler drops it the badge can never appear.
  test('a full_recon job carries its degradedSources; a queue run reports null', async () => {
    h.jobFindMany.mockResolvedValue([
      { id: 'j1', kind: 'full_recon', trigger: 'manual', mode: 'new', status: 'completed',
        startedAt: null, finishedAt: null, createdAt: new Date('2026-08-09T10:00:00Z'),
        nodeCount: 5, ramReason: null, degradedSources: 3, scheduleId: null, version: null },
    ])
    h.queueFindMany.mockResolvedValue([
      { id: 'q1', kind: 'trufflehog', status: 'failed', error: 'exit 2', blockedReason: '',
        enqueuedAt: new Date('2026-08-09T12:00:00Z'), startedAt: null, finishedAt: null,
        scheduleId: null },
    ])
    const body = await (await GET(get(), params('p1'))).json()
    const byId = Object.fromEntries(body.jobs.map((j: { id: string }) => [j.id, j]))
    expect(byId.j1.degradedSources).toBe(3)
    expect(byId.q1.degradedSources).toBeNull()
  })

  test('a clean full_recon job reports degradedSources as-is (0 or null)', async () => {
    h.jobFindMany.mockResolvedValue([
      { id: 'j0', kind: 'full_recon', trigger: 'manual', mode: 'new', status: 'completed',
        startedAt: null, finishedAt: null, createdAt: new Date(), nodeCount: 5, ramReason: null,
        degradedSources: 0, scheduleId: null, version: null },
    ])
    const body = await (await GET(get(), params('p1'))).json()
    expect(body.jobs[0].degradedSources).toBe(0)
  })
})

describe('POST — BOLA', () => {
  test("EXPLOIT: scheduling a scan on another user's project → 404, nothing created", async () => {
    h.requireProjectAccess.mockResolvedValue(NOT_FOUND)
    const res = await POST(post({ mode: 'interval', intervalMinutes: 60 }), params('victimProj'))
    expect(res.status).toBe(404)
    expect(h.create).not.toHaveBeenCalled()
  })

  test('the schedule is owned by the EFFECTIVE user, not a body-supplied id', async () => {
    await POST(post({ mode: 'interval', intervalMinutes: 60, userId: 'someone-else' }), params('p1'))
    expect(h.create.mock.calls[0][0].data.userId).toBe('owner')
  })
})

describe('POST — validation', () => {
  test.each([
    ['unknown mode', { mode: 'hourly' }],
    ['a past one-off', { mode: 'once', runAt: '2000-01-01T00:00:00Z' }],
    ['an interval below the minimum', { mode: 'interval', intervalMinutes: 1 }],
    ['an every-minute cron', { mode: 'cron', cronExpr: '* * * * *' }],
    ['a malformed cron', { mode: 'cron', cronExpr: 'whenever' }],
  ])('rejects %s with 400 and creates nothing', async (_d, body) => {
    const res = await POST(post(body), params('p1'))
    expect(res.status).toBe(400)
    expect(h.create).not.toHaveBeenCalled()
  })

  test('creates a valid cron schedule and audits it', async () => {
    const res = await POST(post({ mode: 'cron', cronExpr: '0 3 * * *', scanMode: 'new' }), params('p1'))
    expect(res.status).toBe(200)
    const data = h.create.mock.calls[0][0].data
    expect(data).toMatchObject({ projectId: 'p1', mode: 'cron', cronExpr: '0 3 * * *', scanMode: 'new' })
    expect(data.nextRunAt).toBeInstanceOf(Date)
    expect(data.estimatedEnvelopeBytes).toBe(BigInt(2000 * MB))
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({ action: 'scan-schedule.create' }))
  })
})

describe('POST — a scope the current rules refuse (WEB-31)', () => {
  test('an enabled schedule is refused with 422 scope_invalid, naming the entry', async () => {
    h.projectFind.mockResolvedValue({
      ipMode: false, domainBatchMode: true, targetDomain: '', subdomainList: [],
      domainBatchHosts: ['www.example.com', '*.co.uk'],
    })
    const res = await POST(post({ mode: 'interval', intervalMinutes: 60 }), params('p1'))
    expect(res.status).toBe(422)
    const body = await res.json()
    expect(body.code).toBe('scope_invalid')
    expect(body.error).toContain('*.co.uk')
    expect(h.create).not.toHaveBeenCalled()
  })

  test('a disabled one may be created, to enable once the target is fixed', async () => {
    h.projectFind.mockResolvedValue({ ipMode: false, domainBatchMode: false, targetDomain: 'co.uk', subdomainList: [] })
    const res = await POST(post({ mode: 'interval', intervalMinutes: 60, enabled: false }), params('p1'))
    expect(res.status).toBe(200)
    expect(h.create.mock.calls[0][0].data.enabled).toBe(false)
  })
})

describe('POST — static RAM feasibility (Section 7.3)', () => {
  test('rejects a schedule whose envelope alone exceeds the pool', async () => {
    h.envelope.mockResolvedValue({ envelopeBytes: 9000 * MB, scanPoolBytes: 8000 * MB })
    const res = await POST(post({ mode: 'interval', intervalMinutes: 60 }), params('p1'))
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.limit).toMatchObject({ limitType: 'ram', reason: 'never-admittable' })
    expect(h.create).not.toHaveBeenCalled()
  })

  test('rejects a run that overlaps others beyond the pool, naming the conflicts', async () => {
    h.envelope.mockResolvedValue({ envelopeBytes: 4000 * MB, scanPoolBytes: 6000 * MB })
    // Overlap is GLOBAL: other projects' schedules count against the same pool.
    h.findMany.mockResolvedValue([
      { id: 'other1', nextRunAt: new Date(Date.now() + 60 * 60_000), estimatedEnvelopeBytes: BigInt(4000 * MB) },
    ])
    const res = await POST(post({ mode: 'interval', intervalMinutes: 60 }), params('p1'))
    expect(res.status).toBe(409)
    expect((await res.json()).limit).toMatchObject({ reason: 'overlap', conflictingScheduleIds: ['other1'] })
    expect(h.create).not.toHaveBeenCalled()
  })

  test('an unavailable envelope skips the courtesy check rather than blocking creation', async () => {
    h.envelope.mockResolvedValue(null)
    const res = await POST(post({ mode: 'interval', intervalMinutes: 60 }), params('p1'))
    expect(res.status).toBe(200)
    expect(h.create.mock.calls[0][0].data.estimatedEnvelopeBytes).toBeNull()
  })
})
