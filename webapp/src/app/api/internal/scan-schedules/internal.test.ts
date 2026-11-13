/**
 * Scan Timeline — the scheduler's internal API (Section 7.2, F3).
 *
 * These three endpoints are reachable ONLY with the internal key (the orchestrator
 * worker), so the first thing each must do is reject anything else. Beyond that:
 * `/run` must go through the SAME start path a manual scan uses, and `/defer`
 * must record why nothing ran and push the schedule out so the worker cannot
 * hot-loop.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  isInternal: vi.fn(),
  findScheduleMany: vi.fn(),
  projectFindMany: vi.fn(),
  findSchedule: vi.fn(),
  updateSchedule: vi.fn(),
  updateManySchedule: vi.fn(),
  countJobs: vi.fn(),
  start: vi.fn(),
  createJob: vi.fn(),
  enqueue: vi.fn(),
  audit: vi.fn(),
  agent: vi.fn(),
  jqFindFirst: vi.fn(),
  projectFindUnique: vi.fn(),
  userFindMany: vi.fn(),
  actorRefusal: vi.fn(),
  notice: vi.fn(),
}))

vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => h.isInternal(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    scanSchedule: {
      findMany: (...a: unknown[]) => h.findScheduleMany(...a),
      findUnique: (...a: unknown[]) => h.findSchedule(...a),
      update: (...a: unknown[]) => h.updateSchedule(...a),
      updateMany: (...a: unknown[]) => h.updateManySchedule(...a),
    },
    scanJob: { count: (...a: unknown[]) => h.countJobs(...a) },
    project: {
      findMany: (...a: unknown[]) => h.projectFindMany(...a),
      findUnique: (...a: unknown[]) => h.projectFindUnique(...a),
    },
    user: { findMany: (...a: unknown[]) => h.userFindMany(...a) },
    jobQueue: { findFirst: (...a: unknown[]) => h.jqFindFirst(...a) },
  },
}))
vi.mock('@/lib/agentSessions', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/agentSessions')>()),
  checkAgentSessions: (...a: unknown[]) => h.agent(...a),
}))
vi.mock('@/lib/startFullScan', () => ({ startFullScan: (...a: unknown[]) => h.start(...a) }))
vi.mock('@/lib/enqueueJob', () => ({ enqueueJob: (...a: unknown[]) => h.enqueue(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
// The actor's project access (step 5.5) runs the real can(); its own tests are
// scanActor.access.test.ts and internal/deferredActor.shares.test.ts. Here it answers "allowed"
// unless a test says otherwise.
vi.mock('@/lib/authz/scanActor', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/scanActor')>()),
  actorScanRefusal: (...a: unknown[]) => h.actorRefusal(...a),
  noticeSchedulePaused: (...a: unknown[]) => h.notice(...a),
}))
vi.mock('@/lib/scanTimeline', async orig => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  createScanJob: (...a: unknown[]) => h.createJob(...a),
}))

import { GET as due } from './due/route'
import { POST as run } from './[scheduleId]/run/route'

const req = (url: string, body?: unknown) => new NextRequest(url, {
  method: body === undefined ? 'GET' : 'POST',
  ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
})
const sp = (scheduleId: string) => ({ params: Promise.resolve({ scheduleId }) })

const SCHEDULE = {
  id: 's1', projectId: 'p1', userId: 'u1', mode: 'interval', scanMode: 'new',
  intervalMinutes: 60, cronExpr: null, enabled: true, lastRunAt: null,
}

beforeEach(() => {
  vi.clearAllMocks()
  h.isInternal.mockReturnValue(true)
  h.findScheduleMany.mockResolvedValue([])
  h.findSchedule.mockResolvedValue(SCHEDULE)
  h.updateSchedule.mockResolvedValue({})
  h.updateManySchedule.mockResolvedValue({ count: 1 })
  h.countJobs.mockResolvedValue(0)
  h.projectFindMany.mockResolvedValue([])
  h.start.mockResolvedValue({ ok: true, versionId: 'v3', versionSeq: 3, scanJobId: 'job1', frozenVersionId: 'v2' })
  h.createJob.mockResolvedValue({ id: 'job1' })
  h.enqueue.mockResolvedValue({ ok: true, status: 201, id: 'jq1' })
  h.agent.mockResolvedValue('idle')
  h.jqFindFirst.mockResolvedValue(null)
  h.actorRefusal.mockResolvedValue(null)
  h.notice.mockResolvedValue(true)
})

describe('authentication', () => {
  test.each([
    ['due', () => due(req('http://x/api/internal/scan-schedules/due'))],
    ['run', () => run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))],
  ])('%s rejects a non-internal caller with 401 and does no work', async (_name, call) => {
    h.isInternal.mockReturnValue(false)
    const res = await call()
    expect(res.status).toBe(401)
    expect(h.start).not.toHaveBeenCalled()
    expect(h.createJob).not.toHaveBeenCalled()
    expect(h.findScheduleMany).not.toHaveBeenCalled()
  })
})

describe('GET /due', () => {
  test('returns enabled schedules whose next run has passed', async () => {
    await due(req('http://x/api/internal/scan-schedules/due'))
    const where = h.findScheduleMany.mock.calls[0][0].where
    expect(where.enabled).toBe(true)
    expect(where.nextRunAt.lte).toBeInstanceOf(Date)
  })

  test('resolves activation state for N projects in ONE query, not N (no N+1)', async () => {
    // The worker polls this every tick; one lock query per due project turned a
    // 25-schedule tick into 25 sequential round-trips.
    h.findScheduleMany.mockResolvedValue(
      Array.from({ length: 8 }, (_, i) => ({
        id: `s${i}`, projectId: `p${i}`, userId: 'u1', mode: 'cron', scanMode: 'new',
        nextRunAt: new Date(), estimatedEnvelopeBytes: null,
      }))
    )
    await due(req('http://x/api/internal/scan-schedules/due'))
    expect(h.projectFindMany).toHaveBeenCalledTimes(1)
    expect(h.projectFindMany.mock.calls[0][0].where.id.in).toHaveLength(8)
  })

  test('flags projects whose graph is mid-activation (F3)', async () => {
    h.findScheduleMany.mockResolvedValue([
      { id: 's1', projectId: 'p1', userId: 'u1', mode: 'cron', scanMode: 'new', nextRunAt: new Date(), estimatedEnvelopeBytes: null },
      { id: 's2', projectId: 'p2', userId: 'u1', mode: 'cron', scanMode: 'new', nextRunAt: new Date(), estimatedEnvelopeBytes: null },
    ])
    h.projectFindMany.mockResolvedValue([
      { id: 'p2', activationState: 'activating', activationStartedAt: new Date() },
    ])
    const body = await (await due(req('http://x/api/internal/scan-schedules/due'))).json()
    expect(body.schedules.map((s: { activationInProgress: boolean }) => s.activationInProgress))
      .toEqual([false, true])
  })
})

describe('POST /run', () => {
  test('starts through the shared start path, tagged as scheduled', async () => {
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(200)
    // quietTransient: a schedule fires headless and enqueues a transient refusal,
    // so the start path must not record a failed ScanJob for it (plan 12.6).
    expect(h.start).toHaveBeenCalledWith({
      projectId: 'p1', mode: 'new', trigger: 'scheduled', actorUserId: 'u1', scheduleId: 's1',
      quietTransient: true,
    })
    expect((await res.json()).ok).toBe(true)
  })

  test('advances nextRunAt after a run', async () => {
    await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    const data = h.updateSchedule.mock.calls[0][0].data
    expect(data.lastRunAt).toBeInstanceOf(Date)
    expect(data.nextRunAt).toBeInstanceOf(Date)
  })

  test('a run never writes enabled back, so a pause made while it started survives', async () => {
    // update_project_scope pauses the schedules when a batch gains hosts. Writing
    // back the `enabled: true` read before the multi-second start re-enabled a
    // schedule paused in between, and its next run reached the new hosts unwatched.
    await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    const data = h.updateSchedule.mock.calls[0][0].data
    expect(data).not.toHaveProperty('enabled')
  })

  test('a one-off schedule is spent after firing', async () => {
    h.findSchedule.mockResolvedValue({ ...SCHEDULE, mode: 'once', intervalMinutes: null })
    await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    const data = h.updateSchedule.mock.calls[0][0].data
    expect(data.enabled).toBe(false)
    expect(data.nextRunAt).toBeNull()
  })

  test('a RAM refusal ENQUEUES the occurrence instead of burning it (Phase 4)', async () => {
    h.start.mockResolvedValue({ ok: false, status: 429, error: 'no memory', limit: { limitType: 'ram' }, scanJobId: 'job9' })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.ok).toBe(false)
    expect(body.queued).toBe(true)
    expect(body.jobId).toBe('jq1')
    // The schedule still rolls forward (the occurrence became a queue row).
    expect(h.updateSchedule).toHaveBeenCalled()
    expect(h.enqueue).toHaveBeenCalledWith(expect.objectContaining({
      projectId: 'p1', kind: 'full_recon', scheduleId: 's1', priority: 0,
    }))
    // No duplicate failed ScanJob for a temporary refusal.
    expect(h.createJob).not.toHaveBeenCalled()
  })

  test('a busy 409 refusal enqueues rather than recording a failed run', async () => {
    h.start.mockResolvedValue({
      ok: false, status: 409,
      error: 'Cannot start a scan while a full recon scan is running for this project. Stop it first.',
      busy: 'a full recon scan is running',
    })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(200)
    expect((await res.json()).queued).toBe(true)
    expect(h.enqueue).toHaveBeenCalled()
    expect(h.createJob).not.toHaveBeenCalled()
    expect(h.updateSchedule).toHaveBeenCalled()
  })

  test('an activation in progress enqueues (F3 preserved: nothing spawns)', async () => {
    h.start.mockResolvedValue({
      ok: false, status: 409, error: 'A version activation is in progress', activationInProgress: true,
    })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect((await res.json()).queued).toBe(true)
    expect(h.enqueue).toHaveBeenCalled()
  })

  test('a PERMANENT failure records a failed ScanJob and does not enqueue', async () => {
    h.start.mockResolvedValue({ ok: false, status: 400, error: 'Project has no target domain configured' })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(200)
    expect(h.enqueue).not.toHaveBeenCalled()
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed', scheduleId: 's1' }))
  })

  // WEB-31: a schedule fires headless, so a saved scope the rules now refuse
  // would fail on every tick. It is paused, with an audit row saying why.
  test('a scope_invalid refusal records a failed run, pauses the schedule and audits the pause', async () => {
    const invalidEntries = [{ entry: '*.com.vn', reason: 'wildcard_on_suffix' }]
    h.start.mockResolvedValue({
      ok: false, status: 422, code: 'scope_invalid', invalidEntries,
      error: 'The saved scope is no longer valid. Not accepted: *.com.vn (a wildcard on a public suffix). Edit the target list before scanning.',
    })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ ok: false, paused: true, code: 'scope_invalid' })
    expect(h.enqueue).not.toHaveBeenCalled()
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({
      status: 'failed', scheduleId: 's1', ramReason: expect.stringContaining('*.com.vn'),
    }))
    expect(h.updateSchedule).toHaveBeenCalledWith({ where: { id: 's1' }, data: { enabled: false } })
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'schedule.paused', targetId: 's1', source: 'system',
      after: { reason: 'scope_invalid', projectId: 'p1', invalidEntries },
    }))
  })

  test('a temporary refusal keeps the schedule enabled', async () => {
    h.start.mockResolvedValue({ ok: false, status: 429, error: 'no memory', limit: { limitType: 'ram' } })
    await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(h.updateSchedule.mock.calls.map(c => c[0].data)).not.toContainEqual(expect.objectContaining({ enabled: false }))
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('another permanent refusal records the run but does not pause', async () => {
    h.start.mockResolvedValue({ ok: false, status: 422, error: 'no authorization record' })
    const body = await (await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))).json()
    expect(body.paused).toBeUndefined()
    expect(h.updateSchedule).toHaveBeenCalledTimes(1)
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('an answered 503 is transient: enqueued, with no failed ScanJob for the attempt (plan 12.6)', async () => {
    h.start.mockResolvedValue({
      ok: false, status: 503,
      error: 'Cannot verify scan scope: the webapp is unreachable (URLError). Refusing to start.',
    })
    const body = await (await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))).json()
    expect(body).toMatchObject({ ok: false, queued: true, blockedCode: 'transient' })
    expect(h.enqueue).toHaveBeenCalledWith(expect.objectContaining({ kind: 'full_recon', scheduleId: 's1' }))
    expect(h.createJob).not.toHaveBeenCalled()
  })

  test('an unknown start outcome is not enqueued: the failed ScanJob the start wrote stands (plan 12.6)', async () => {
    h.start.mockResolvedValue({
      ok: false, status: 503, startOutcome: 'unknown', scanJobId: 'sj-unknown',
      error: 'The orchestrator did not answer, so it is unknown whether the scan started.',
    })
    const body = await (await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))).json()
    expect(body).toMatchObject({ ok: false, startOutcome: 'unknown', scanJobId: 'sj-unknown' })
    expect(body.queued).toBeUndefined()
    expect(h.enqueue).not.toHaveBeenCalled()
    expect(h.createJob).not.toHaveBeenCalled()
  })

  test('a failed spawn is permanent: recorded, not enqueued (plan 12.9)', async () => {
    h.start.mockResolvedValue({ ok: false, status: 500, code: 'spawn_failed', error: 'image missing', scanJobId: 'sj3' })
    const body = await (await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))).json()
    expect(body.queued).toBeUndefined()
    expect(h.enqueue).not.toHaveBeenCalled()
  })

  describe('an agent session holds the scheduled full recon (plan 12.16)', () => {
    // A full recon clears the graph the agent is working on. The queue's
    // dispatch route already waits for the session; the schedule route did not.
    test('a running session enqueues the occurrence and starts nothing', async () => {
      h.agent.mockResolvedValue('running')
      const body = await (await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))).json()
      expect(h.start).not.toHaveBeenCalled()
      expect(h.enqueue).toHaveBeenCalledWith(expect.objectContaining({
        projectId: 'p1', kind: 'full_recon', payload: { mode: 'new' }, priority: 0, scheduleId: 's1',
      }))
      expect(body).toMatchObject({ ok: false, queued: true, jobId: 'jq1', blockedCode: 'agent_running' })
      expect(body.nextRunAt).toBeTruthy()
      const data = h.updateSchedule.mock.calls[0][0].data
      expect(data.lastRunAt).toBeInstanceOf(Date)
      expect(data.nextRunAt).toBeInstanceOf(Date)
    })

    test('an unverified session also holds it (fail closed)', async () => {
      h.agent.mockResolvedValue('unverified')
      const body = await (await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))).json()
      expect(h.start).not.toHaveBeenCalled()
      expect(body).toMatchObject({ queued: true, blockedCode: 'agent_running' })
    })

    test('a one-off schedule is still spent', async () => {
      h.agent.mockResolvedValue('running')
      h.findSchedule.mockResolvedValue({ ...SCHEDULE, mode: 'once', intervalMinutes: null })
      await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
      expect(h.updateSchedule.mock.calls[0][0].data.enabled).toBe(false)
    })

    test('a second occurrence while one is queued adds no row', async () => {
      h.agent.mockResolvedValue('running')
      h.jqFindFirst.mockResolvedValue({ id: 'jq-earlier', status: 'queued' })
      const body = await (await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))).json()
      expect(h.enqueue).not.toHaveBeenCalled()
      expect(body).toMatchObject({ queued: true, jobId: 'jq-earlier', alreadyQueued: true })
      expect(h.jqFindFirst).toHaveBeenCalledWith(expect.objectContaining({
        where: expect.objectContaining({
          projectId: 'p1', kind: 'full_recon',
          status: { in: ['queued', 'dispatching', 'running', 'needs_review'] },
        }),
      }))
    })

    test('the temporary-refusal branch does not pile up either', async () => {
      h.start.mockResolvedValue({ ok: false, status: 429, error: 'no memory', limit: { limitType: 'ram' } })
      h.jqFindFirst.mockResolvedValue({ id: 'jq-earlier', status: 'queued' })
      const body = await (await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))).json()
      expect(h.enqueue).not.toHaveBeenCalled()
      expect(body).toMatchObject({ queued: true, jobId: 'jq-earlier', alreadyQueued: true })
    })

    test('an idle project starts as before', async () => {
      await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
      expect(h.start).toHaveBeenCalled()
      expect(h.agent).toHaveBeenCalledWith('p1')
    })
  })

  test('a disabled schedule is not run', async () => {
    h.findSchedule.mockResolvedValue({ ...SCHEDULE, enabled: false })
    const res = await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1'))
    expect(res.status).toBe(409)
    expect(h.start).not.toHaveBeenCalled()
  })

  test('an unknown schedule is a 404', async () => {
    h.findSchedule.mockResolvedValue(null)
    expect((await run(req('http://x/api/internal/scan-schedules/nope/run', {}), sp('nope'))).status).toBe(404)
    expect(h.start).not.toHaveBeenCalled()
  })
})


describe('a schedule of an account that is not active (step 2.3, DV-39)', () => {
  const users = (statuses: Record<string, string>) =>
    h.userFindMany.mockImplementation(async ({ where }: { where: { id: { in: string[] } } }) =>
      where.id.in.filter((id) => id in statuses).map((id) => ({ id, status: statuses[id] })))
  const runIt = async () => (await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1')))

  beforeEach(async () => {
    const { setFlagsForTests } = await import('@/lib/authz/flags')
    setFlagsForTests({ identity: true })
    h.projectFindUnique.mockResolvedValue({ userId: 'owner-1' })
    users({ u1: 'active', 'owner-1': 'active' })
    vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(async () => {
    const { setFlagsForTests } = await import('@/lib/authz/flags')
    setFlagsForTests(null)
    vi.restoreAllMocks()
  })

  test("a disabled actor's schedule is skipped and audited; the occurrence advances", async () => {
    users({ u1: 'disabled', 'owner-1': 'active' })
    const res = await runIt()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toMatchObject({ ok: false, skipped: 'actor_inactive', error: 'skipped: the account that scheduled it is disabled' })
    expect(body.nextRunAt).toBeTruthy()
    expect(h.start).not.toHaveBeenCalled()
    expect(h.agent).not.toHaveBeenCalled()
    expect(h.enqueue).not.toHaveBeenCalled()
    expect(h.updateSchedule).toHaveBeenCalledTimes(1)
    expect(h.updateSchedule.mock.calls[0][0].data.nextRunAt).toBeInstanceOf(Date)
    expect(h.audit).toHaveBeenCalledWith({
      actorId: null, action: 'scan_schedule.skipped', targetType: 'scanSchedule', targetId: 's1',
      after: { reason: 'actor_inactive', projectId: 'p1', userId: 'u1', account: 'actor', status: 'disabled' },
      source: 'system',
    })
  })

  test("a disabled owner's schedule is skipped", async () => {
    users({ u1: 'active', 'owner-1': 'disabled' })
    const body = await (await runIt()).json()
    expect(body).toMatchObject({ skipped: 'actor_inactive', error: "skipped: the project owner's account is disabled" })
    expect(h.start).not.toHaveBeenCalled()
    expect(h.audit.mock.calls[0][0].after).toMatchObject({ userId: 'owner-1', account: 'owner' })
    expect(h.projectFindUnique).toHaveBeenCalledWith({ where: { id: 'p1' }, select: { userId: true } })
  })

  test('an account that no longer exists counts as not active', async () => {
    users({ 'owner-1': 'active' })
    expect((await (await runIt()).json()).skipped).toBe('actor_inactive')
    expect(h.audit.mock.calls[0][0].after).toMatchObject({ userId: 'u1', status: 'deleted' })
  })

  test('the actor and the owner are read in one query', async () => {
    await runIt()
    expect(h.userFindMany).toHaveBeenCalledTimes(1)
    expect(h.userFindMany.mock.calls[0][0]).toEqual({ where: { id: { in: ['u1', 'owner-1'] } }, select: { id: true, status: true } })
  })

  test('enabled again → the next occurrence fires', async () => {
    users({ u1: 'disabled', 'owner-1': 'active' })
    expect((await (await runIt()).json()).skipped).toBe('actor_inactive')
    users({ u1: 'active', 'owner-1': 'active' })
    const body = await (await runIt()).json()
    expect(body.ok).toBe(true)
    expect(h.start).toHaveBeenCalledTimes(1)
    expect(h.start.mock.calls[0][0]).toMatchObject({ actorUserId: 'u1', trigger: 'scheduled' })
  })

  test('a schedule paused by a person is still refused first, without advancing', async () => {
    users({ u1: 'disabled', 'owner-1': 'active' })
    h.findSchedule.mockResolvedValue({ ...SCHEDULE, enabled: false })
    expect((await runIt()).status).toBe(409)
    expect(h.updateSchedule).not.toHaveBeenCalled()
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('switch off → today\'s behaviour: no account read, the scan starts', async () => {
    const { setFlagsForTests } = await import('@/lib/authz/flags')
    setFlagsForTests({ identity: false })
    users({ u1: 'disabled', 'owner-1': 'disabled' })
    expect((await (await runIt()).json()).ok).toBe(true)
    expect(h.start).toHaveBeenCalled()
    expect(h.userFindMany).not.toHaveBeenCalled()
    expect(h.projectFindUnique).not.toHaveBeenCalled()
  })
})

describe('POST /run: a schedule whose actor lost access to the project (step 5.5, DV-38, D-13)', () => {
  const runIt = async () => (await run(req('http://x/api/internal/scan-schedules/s1/run', {}), sp('s1')))
  const LOST = { userId: 'collab-1', permission: 'recon:scan', reason: 'project_level' }

  beforeEach(() => {
    h.findSchedule.mockResolvedValue({ ...SCHEDULE, userId: 'collab-1', label: 'nightly' })
    vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => vi.restoreAllMocks())

  test('schedule paused with a reason: audited, logged, nothing starts, never re-attributed', async () => {
    h.actorRefusal.mockResolvedValue(LOST)
    const res = await runIt()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toMatchObject({
      ok: false, paused: true, code: 'actor_no_access',
      error: 'paused: the account that scheduled it no longer has the access to this project that recon:scan needs',
    })
    expect(h.start).not.toHaveBeenCalled()
    expect(h.enqueue).not.toHaveBeenCalled()
    expect(h.actorRefusal).toHaveBeenCalledWith('collab-1', 'p1', ['recon:scan'])
    expect(h.updateSchedule).not.toHaveBeenCalled()
    expect(h.updateManySchedule).toHaveBeenCalledTimes(1)
    const update = h.updateManySchedule.mock.calls[0][0]
    expect(update.where).toEqual({ id: 's1', userId: 'collab-1' })
    expect(update.data).toMatchObject({
      enabled: false, pausedReason: 'actor_no_access', lastRunAt: expect.any(Date), nextRunAt: expect.any(Date),
    })
    // D-13: the schedule keeps its actor until a person confirms it.
    expect(update.data).not.toHaveProperty('userId')
    expect(h.audit).toHaveBeenCalledWith({
      actorId: null, projectId: 'p1', action: 'scan_schedule.paused', targetType: 'scanSchedule', targetId: 's1',
      after: { reason: 'actor_no_access', projectId: 'p1', userId: 'collab-1', permission: 'recon:scan', refusal: 'project_level' },
      source: 'system',
    })
    expect(console.warn).toHaveBeenCalledWith(
      '[rbac] schedule s1 paused: actor collab-1 lost recon:scan on project p1 (project_level)')
    // The owner is told (the notice helper reads the owner and writes the notice itself).
    expect(h.notice).toHaveBeenCalledWith({ projectId: 'p1', scheduleId: 's1', label: 'nightly', actorUserId: 'collab-1' })
  })

  test('a notice that cannot be written leaves the pause standing', async () => {
    h.actorRefusal.mockResolvedValue(LOST)
    h.notice.mockResolvedValue(false)
    const body = await (await runIt()).json()
    expect(body).toMatchObject({ paused: true, code: 'actor_no_access' })
    expect(h.updateManySchedule).toHaveBeenCalledTimes(1)
  })

  test('a confirmation that landed while it fired is not undone (two at once)', async () => {
    h.actorRefusal.mockResolvedValue(LOST)
    h.updateManySchedule.mockResolvedValue({ count: 0 })
    vi.spyOn(console, 'info').mockImplementation(() => {})
    const res = await runIt()
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ ok: false, skipped: 'actor_changed' })
    expect(h.start).not.toHaveBeenCalled()
    expect(h.audit).not.toHaveBeenCalled()
    expect(h.notice).not.toHaveBeenCalled()
  })

  test('an overwrite schedule needs recon:overwrite of its actor too', async () => {
    h.findSchedule.mockResolvedValue({ ...SCHEDULE, userId: 'collab-1', scanMode: 'overwrite' })
    await runIt()
    expect(h.actorRefusal).toHaveBeenCalledWith('collab-1', 'p1', ['recon:scan', 'recon:overwrite'])
  })

  test('owner schedules unchanged: the check passes and the scan starts as its actor', async () => {
    h.findSchedule.mockResolvedValue(SCHEDULE)
    const body = await (await runIt()).json()
    expect(body.ok).toBe(true)
    expect(h.actorRefusal).toHaveBeenCalledWith('u1', 'p1', ['recon:scan'])
    expect(h.start.mock.calls[0][0]).toMatchObject({ actorUserId: 'u1', scheduleId: 's1', trigger: 'scheduled' })
    expect(h.audit).not.toHaveBeenCalled()
    expect(h.notice).not.toHaveBeenCalled()
  })

  test('an access check that cannot be read starts nothing and keeps the occurrence due (never)', async () => {
    h.actorRefusal.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await runIt()
    expect(res.status).toBe(500)
    expect(h.start).not.toHaveBeenCalled()
    expect(h.updateSchedule).not.toHaveBeenCalled()
    expect(h.updateManySchedule).not.toHaveBeenCalled()
  })

  test('a schedule a person already turned off is refused before any access check', async () => {
    h.findSchedule.mockResolvedValue({ ...SCHEDULE, userId: 'collab-1', enabled: false })
    expect((await runIt()).status).toBe(409)
    expect(h.actorRefusal).not.toHaveBeenCalled()
  })
})
