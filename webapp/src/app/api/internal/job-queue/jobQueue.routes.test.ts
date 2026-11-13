/**
 * Scan Queue — the dispatcher's internal API (plan Phase 2). Internal-key only, so
 * each route rejects non-internal first. Beyond that the DISPATCH route is the
 * fail-closed core: project gone -> failed, settings fingerprint changed ->
 * needs_review with NO start call (C-4), another job for the project -> busy,
 * agent running + full_recon -> deferred (C-5), else the same start path a button
 * uses. The RECONCILE route closes finished 'running' rows even with no browser
 * (C-6), and never closes a still-active one.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { settingsFingerprint, nextBackoff } from '@/lib/jobQueue'

const h = vi.hoisted(() => ({
  isInternal: vi.fn(),
  jqFindUnique: vi.fn(),
  jqUpdateMany: vi.fn(),
  jqFindFirst: vi.fn(),
  jqUpdate: vi.fn(),
  jqFindMany: vi.fn(),
  jqCount: vi.fn(),
  sjFindMany: vi.fn(),
  // Set in beforeEach: answers each sweep query with the rows its filter selects.
  sweep: (() => {}) as (rows: unknown[]) => void,
  sjUpdateMany: vi.fn(),
  projectFindUnique: vi.fn(),
  agentState: vi.fn(),
  dispatchStart: vi.fn(),
  stopScan: vi.fn(),
  orchFetch: vi.fn(),
  userFindMany: vi.fn(),
  audit: vi.fn(),
  actorRefusal: vi.fn(),
}))

vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => h.isInternal(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    jobQueue: {
      findUnique: (...a: unknown[]) => h.jqFindUnique(...a),
      updateMany: (...a: unknown[]) => h.jqUpdateMany(...a),
      findFirst: (...a: unknown[]) => h.jqFindFirst(...a),
      update: (...a: unknown[]) => h.jqUpdate(...a),
      findMany: (...a: unknown[]) => h.jqFindMany(...a),
      count: (...a: unknown[]) => h.jqCount(...a),
    },
    scanJob: {
      findMany: (...a: unknown[]) => h.sjFindMany(...a),
      updateMany: (...a: unknown[]) => h.sjUpdateMany(...a),
    },
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
    user: { findMany: (...a: unknown[]) => h.userFindMany(...a) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
// The actor's project access (step 5.5) runs the real can(); its own tests are
// scanActor.access.test.ts and internal/deferredActor.shares.test.ts. Here it answers "allowed"
// unless a test says otherwise.
vi.mock('@/lib/authz/scanActor', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/scanActor')>()),
  actorScanRefusal: (...a: unknown[]) => h.actorRefusal(...a),
}))
vi.mock('@/lib/startScan', () => ({
  dispatchStart: (...a: unknown[]) => h.dispatchStart(...a),
  stopScan: (...a: unknown[]) => h.stopScan(...a),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchFetch(...a) }))
vi.mock('@/lib/agentSessions', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/agentSessions')>()),
  checkAgentSessions: (...a: unknown[]) => h.agentState(...a),
}))

import { POST as dispatch } from './[id]/dispatch/route'
import { GET as candidates } from './candidates/route'
import { POST as reconcile } from './reconcile/route'

const PROJECT = {
  id: 'p1', userId: 'u1', targetDomain: 'example.com', ipMode: false,
  targetIps: [], scanModules: ['port_scan'], targetGuardrailEnabled: true, stealthMode: false,
}
const HASH = settingsFingerprint('full_recon', PROJECT as unknown as Record<string, unknown>)

function baseRow(over: Record<string, unknown> = {}) {
  return {
    id: 'j1', projectId: 'p1', userId: 'u1', kind: 'full_recon', payload: {},
    settingsHash: HASH, status: 'queued', attempts: 0, maxAttempts: 20, ...over,
  }
}

interface SweepRow { id: string; projectId: string; kind: string; runId?: string; startedAt?: Date | null }
interface SweepWhere {
  kind: { in: string[] }
  projectId?: { in?: string[]; notIn?: string[] }
  OR?: { startedAt: null | { lte: Date } }[]
}

function sweepSelects(where: SweepWhere, row: SweepRow): boolean {
  if (!where.kind.in.includes(row.kind)) return false
  if (where.projectId?.notIn?.includes(row.projectId)) return false
  if (where.projectId?.in && !where.projectId.in.includes(row.projectId)) return false
  const lte = where.OR?.map(c => c.startedAt).find((s): s is { lte: Date } => !!s && 'lte' in s)?.lte
  if (lte && row.startedAt && row.startedAt > lte) return false
  return true
}

const post = (url: string, body: unknown = {}) => new NextRequest(url, {
  method: 'POST', headers: { 'x-internal-key': 'k' }, body: JSON.stringify(body),
})
const get = (url: string) => new NextRequest(url, { method: 'GET', headers: { 'x-internal-key': 'k' } })
const sp = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.isInternal.mockReturnValue(true)
  h.jqFindUnique.mockResolvedValue(baseRow())
  h.jqUpdateMany.mockResolvedValue({ count: 1 })
  h.jqFindFirst.mockResolvedValue(null)
  h.jqUpdate.mockResolvedValue({})
  h.jqFindMany.mockResolvedValue([])
  h.jqCount.mockResolvedValue(0)
  h.sjFindMany.mockResolvedValue([])
  // Several sweep queries run per tick (one-per-project kinds; run-keyed kinds
  // of idle projects; run-keyed kinds of active projects). Each is answered with
  // the rows its where clause selects, as the database would, so no row reaches
  // two sweeps and a query's own filter is what keeps a row out of it.
  h.sweep = (rows: unknown[]) =>
    h.sjFindMany.mockImplementation((args: { where: SweepWhere }) =>
      Promise.resolve((rows as SweepRow[]).filter(r => sweepSelects(args.where, r))))
  h.sjUpdateMany.mockResolvedValue({ count: 1 })
  h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'idle' }) })
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.agentState.mockResolvedValue('idle')
  h.dispatchStart.mockResolvedValue({ ok: true, runId: 'r1', scanJobId: 'sj1' })
  h.stopScan.mockResolvedValue(undefined)
  h.actorRefusal.mockResolvedValue(null)
})

describe('dispatch route auth', () => {
  test('rejects a non-internal caller', async () => {
    h.isInternal.mockReturnValue(false)
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect(res.status).toBe(401)
    expect(h.dispatchStart).not.toHaveBeenCalled()
  })
})

describe('dispatch route fail-closed checks', () => {
  test('a changed settings fingerprint -> needs_review and NO start call (C-4)', async () => {
    h.jqFindUnique.mockResolvedValue(baseRow({ settingsHash: 'stale-hash' }))
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.needsReview).toBe(true)
    expect(h.dispatchStart).not.toHaveBeenCalled()
    // Guarded on status='dispatching' (Finding 1b) so a racing cancel is not overwritten.
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 'j1', status: 'dispatching' }),
      data: expect.objectContaining({ status: 'needs_review', blockedCode: 'settings_changed' }),
    }))
  })

  test('a deleted project -> failed, never dispatches (C-7)', async () => {
    h.projectFindUnique.mockResolvedValue(null)
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.ok).toBe(false)
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'failed' }),
    }))
  })

  test('another running job for the project -> busy, no start (C-12)', async () => {
    h.jqFindFirst.mockResolvedValue({ id: 'other' })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.blocked).toBe('busy')
    expect(h.dispatchStart).not.toHaveBeenCalled()
  })

  test('agent running + full_recon -> deferred, no start (C-5)', async () => {
    h.agentState.mockResolvedValue('running')
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.blocked).toBe('agent_running')
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        status: 'queued',
        blockedCode: 'agent_running',
        blockedReason: 'an agent session is running for this project; a full recon would wipe its graph',
      }),
    }))
  })

  test('a session flag the agent could not confirm also defers, saying so (C-8)', async () => {
    h.agentState.mockResolvedValue('unverified')
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect((await res.json()).blocked).toBe('agent_running')
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ blockedReason: expect.stringMatching(/could not be reached to confirm it/) }),
    }))
  })

  test('a stale flag the agent disowns does not block the dispatch (C-8)', async () => {
    // checkAgentSessions cleared it and answered idle.
    h.agentState.mockResolvedValue('idle')
    await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect(h.agentState).toHaveBeenCalledWith(PROJECT.id)
    expect(h.dispatchStart).toHaveBeenCalled()
  })

  test('a claim lost to a concurrent dispatch -> 409, no start', async () => {
    h.jqUpdateMany.mockResolvedValue({ count: 0 })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect(res.status).toBe(409)
    expect(h.dispatchStart).not.toHaveBeenCalled()
  })
})

describe('dispatch route happy + failure paths', () => {
  test('all checks pass -> running (conditional on still dispatching), start called, ids recorded', async () => {
    // claim updateMany -> {count:1}; success updateMany -> {count:1} (won the race)
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.ok).toBe(true)
    expect(h.dispatchStart).toHaveBeenCalledWith('full_recon', 'p1', expect.objectContaining({ actorUserId: 'u1' }))
    // The success write is guarded on status='dispatching' so a concurrent cancel wins.
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 'j1', status: 'dispatching' }),
      data: expect.objectContaining({ status: 'running', runId: 'r1', scanJobId: 'sj1' }),
    }))
    expect(h.stopScan).not.toHaveBeenCalled()
  })

  test('regression F1: a cancel during dispatch is NOT resurrected; the started scan is stopped', async () => {
    // claim wins (count 1); the success write loses because a cancel flipped the row
    // out of 'dispatching' (count 0).
    h.jqUpdateMany
      .mockResolvedValueOnce({ count: 1 })   // claim
      .mockResolvedValueOnce({ count: 0 })   // success write lost to the cancel
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.ok).toBe(false)
    expect(body.canceledDuringDispatch).toBe(true)
    // The scan already started, so it must be stopped rather than left orphaned.
    expect(h.stopScan).toHaveBeenCalledWith('full_recon', 'p1', 'r1')
  })

  test('a RAM capacity wait requeues WITHOUT spending an attempt (guarded on dispatching)', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 429, error: 'no mem', limit: { limitType: 'ram' } })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.temporary).toBe(true)
    const call = h.jqUpdateMany.mock.calls.find(c => c[0]?.data?.status === 'queued')!
    expect(call[0].where).toMatchObject({ id: 'j1', status: 'dispatching' })
    expect(call[0].data).toMatchObject({ status: 'queued', blockedCode: 'ram' })
    // A capacity wait must NOT consume the attempt budget (that would delay the
    // eventual promotion and eventually fail a job that only waited its turn).
    expect(call[0].data.attempts).toBeUndefined()
    expect(call[0].data.notBefore).toBeInstanceOf(Date)
  })

  test('a hard concurrency-cap refusal also requeues without spending an attempt', async () => {
    h.dispatchStart.mockResolvedValue({
      ok: false, status: 409, error: '2 of 2 concurrent scans allowed per user',
      limit: { limitType: 'hard' },
    })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect((await res.json()).blocked).toBe('hard')
    const call = h.jqUpdateMany.mock.calls.find(c => c[0]?.data?.status === 'queued')!
    expect(call[0].data).toMatchObject({ status: 'queued', blockedCode: 'hard' })
    expect(call[0].data.attempts).toBeUndefined()
  })

  // The regression that this stress test surfaced: a job waiting behind long-running
  // scans must NOT be failed just because it was bounced many times on capacity.
  test('a capacity wait NEVER fails, even at a high attempt count', async () => {
    h.jqFindUnique.mockResolvedValue(baseRow({ attempts: 19, maxAttempts: 20 }))
    h.dispatchStart.mockResolvedValue({ ok: false, status: 429, error: 'no mem', limit: { limitType: 'ram' } })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.failed).toBeUndefined()
    expect(body.temporary).toBe(true)
    const call = h.jqUpdateMany.mock.calls.find(c => c[0]?.data?.status === 'queued')!
    expect(call[0].data.status).toBe('queued')
  })

  test('a permanent refusal fails the job', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 400, error: 'bad config' })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.failed).toBe(true)
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'failed' }),
    }))
  })
  test('a scope_invalid refusal (422) fails the job on its first attempt, naming the entries', async () => {
    // A 409 would read as "busy" and requeue for ever without spending an
    // attempt; a saved scope the rules now refuse only a person can fix.
    h.dispatchStart.mockResolvedValue({
      ok: false, status: 422,
      error: 'The saved scope is no longer valid. Not accepted: *.com.vn (a public suffix). Edit the target list before scanning.',
    })
    const body = await (await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))).json()
    expect(body.failed).toBe(true)
    const final = h.jqUpdateMany.mock.calls.at(-1)![0].data
    expect(final).toMatchObject({ status: 'failed', attempts: 1 })
    expect(final.error).toContain('*.com.vn')
  })

  test('a third-party engagement blocker (422) fails the job instead of requeueing it', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 422, error: 'no authorization record' })
    const body = await (await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))).json()
    expect(body.failed).toBe(true)
    expect(h.jqUpdateMany.mock.calls.at(-1)![0].data.status).toBe('failed')
  })
})

describe('dispatch route: transient, unknown and thrown starts (plan 12.6)', () => {
  const NOW = new Date('2026-10-26T12:00:00Z')
  const dispatchOnce = async () =>
    (await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))).json()
  const lastWrite = () => h.jqUpdateMany.mock.calls.at(-1)![0]

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(NOW)
  })
  afterEach(() => { vi.useRealTimers() })

  test('an answered 503 is requeued, spending one attempt, after the first backoff', async () => {
    h.dispatchStart.mockResolvedValue({
      ok: false, status: 503,
      error: 'Cannot verify scan scope: the webapp is unreachable (URLError). Refusing to start.',
    })
    const body = await dispatchOnce()
    expect(body).toMatchObject({ blocked: 'transient', temporary: true })
    expect(lastWrite().where).toMatchObject({ id: 'j1', status: 'dispatching' })
    expect(lastWrite().data).toMatchObject({ status: 'queued', attempts: 1, blockedCode: 'transient' })
    expect(lastWrite().data.notBefore).toEqual(new Date(NOW.getTime() + nextBackoff(1)))
  })

  test('the transient branch gives up at maxAttempts', async () => {
    h.jqFindUnique.mockResolvedValue(baseRow({ attempts: 19, maxAttempts: 20 }))
    h.dispatchStart.mockResolvedValue({ ok: false, status: 500, error: 'boom' })
    const body = await dispatchOnce()
    expect(body.failed).toBe(true)
    expect(lastWrite().data).toMatchObject({ status: 'failed', attempts: 20 })
    expect(lastWrite().data.error).toMatch(/gave up after 20 attempts/)
  })

  test('a failed spawn is permanent on its first attempt', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 500, error: 'image not found', code: 'spawn_failed' })
    expect((await dispatchOnce()).failed).toBe(true)
    expect(lastWrite().data).toMatchObject({ status: 'failed', attempts: 1 })
  })

  test('a 403 (outside the RoE window) still fails at once', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 403, error: 'RoE time window' })
    expect((await dispatchOnce()).failed).toBe(true)
    expect(lastWrite().data.status).toBe('failed')
  })

  test('unknown full_recon with the orchestrator running a scan it started after the claim -> running', async () => {
    h.dispatchStart.mockResolvedValue({
      ok: false, status: 503, startOutcome: 'unknown', error: 'no answer', scanJobId: 'sj9',
    })
    h.orchFetch.mockResolvedValue({
      ok: true, json: async () => ({ status: 'running', started_at: new Date(NOW.getTime() + 1000).toISOString() }),
    })
    const body = await dispatchOnce()
    expect(body).toMatchObject({ ok: true, adopted: true })
    expect(h.orchFetch.mock.calls[0][0]).toMatch(/\/recon\/p1\/status$/)
    expect(lastWrite().data).toMatchObject({ status: 'running', scanJobId: 'sj9' })
    expect(h.sjUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 'sj9' }),
      data: expect.objectContaining({ status: 'running' }),
    }))
  })

  test('unknown full_recon and the orchestrator idle -> requeued as transient', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 503, startOutcome: 'unknown', error: 'no answer' })
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'idle' }) })
    const body = await dispatchOnce()
    expect(body.blocked).toBe('transient')
    expect(lastWrite().data).toMatchObject({ status: 'queued', attempts: 1, blockedCode: 'transient' })
  })

  test('unknown full_recon with a scan that started before the claim is not ours -> requeued', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 503, startOutcome: 'unknown', error: 'no answer' })
    h.orchFetch.mockResolvedValue({
      ok: true, json: async () => ({ status: 'running', started_at: '2026-10-26T11:00:00Z' }),
    })
    expect((await dispatchOnce()).blocked).toBe('transient')
    expect(lastWrite().data.status).toBe('queued')
  })

  test('unknown full_recon with the status unreadable -> needs_review', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 503, startOutcome: 'unknown', error: 'no answer' })
    h.orchFetch.mockRejectedValue(new Error('ECONNREFUSED'))
    const body = await dispatchOnce()
    expect(body.needsReview).toBe(true)
    expect(lastWrite().data).toMatchObject({ status: 'needs_review', blockedCode: 'start_unknown' })
  })

  test('unknown outcome of another kind -> needs_review naming the doubt, with its ScanJob id', async () => {
    h.jqFindUnique.mockResolvedValue(baseRow({
      kind: 'gvm', settingsHash: settingsFingerprint('gvm', PROJECT as unknown as Record<string, unknown>),
    }))
    h.dispatchStart.mockResolvedValue({ ok: false, status: 503, startOutcome: 'unknown', error: 'no answer', scanJobId: 'sj7' })
    const body = await dispatchOnce()
    expect(body.needsReview).toBe(true)
    expect(lastWrite().data).toMatchObject({
      status: 'needs_review', blockedCode: 'start_unknown', scanJobId: 'sj7',
      blockedReason: 'the orchestrator did not answer; check whether the scan started',
    })
    expect(h.orchFetch).not.toHaveBeenCalled()
  })

  test('a thrown error spends an attempt and backs off instead of retrying every tick', async () => {
    h.dispatchStart.mockRejectedValue(new Error('prepareVersions blew up'))
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect(res.status).toBe(500)
    expect(lastWrite().where).toMatchObject({ id: 'j1', status: 'dispatching' })
    expect(lastWrite().data).toMatchObject({ status: 'queued', attempts: 1 })
    expect(lastWrite().data.notBefore).toEqual(new Date(NOW.getTime() + nextBackoff(1)))
  })

  test('a thrown error at maxAttempts fails the job', async () => {
    h.jqFindUnique.mockResolvedValue(baseRow({ attempts: 19, maxAttempts: 20 }))
    h.dispatchStart.mockRejectedValue(new Error('boom'))
    await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect(lastWrite().data).toMatchObject({ status: 'failed', attempts: 20 })
  })
})

describe('candidates route', () => {
  test('returns ordered ready rows + activeCount from the in-flight set', async () => {
    h.jqFindMany
      .mockResolvedValueOnce([{ projectId: 'pBusy' }, { projectId: 'pBusy' }]) // in-flight (2 rows, 1 project)
      .mockResolvedValueOnce([
        { id: 'a', projectId: 'p1', userId: 'u1', kind: 'gvm', envelopeBytes: BigInt(2684354560), priority: 10, enqueuedAt: new Date('2026-08-09T00:00:00Z'), attempts: 0, maxAttempts: 20 },
      ])
    const res = await candidates(get('http://x/api/internal/job-queue/candidates'))
    const body = await res.json()
    expect(body.activeCount).toBe(2)
    expect(body.candidates[0]).toMatchObject({ id: 'a', kind: 'gvm', envelopeBytes: 2684354560 })
  })

  test('regression F2: queued jobs of an already-busy project are excluded from candidates', async () => {
    h.jqFindMany
      .mockResolvedValueOnce([{ projectId: 'pBusy' }]) // in-flight for pBusy
      .mockResolvedValueOnce([])
    await candidates(get('http://x/api/internal/job-queue/candidates'))
    // The queued query must exclude pBusy, so its big head job can't trip the
    // dispatcher's head-of-line RAM break and starve other tenants.
    expect(h.jqFindMany).toHaveBeenLastCalledWith(expect.objectContaining({
      where: expect.objectContaining({ projectId: { notIn: ['pBusy'] } }),
    }))
  })

  test('rejects non-internal', async () => {
    h.isInternal.mockReturnValue(false)
    const res = await candidates(get('http://x/api/internal/job-queue/candidates'))
    expect(res.status).toBe(401)
  })
})

describe('reconcile route (C-6)', () => {
  test('closes a running row whose project is no longer active and past grace', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) },
    ])
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p2'] }))
    const body = await res.json()
    expect(body.closed).toBe(1)
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'done' }),
    }))
  })

  test('does NOT close a row whose project is still active', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) },
    ])
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    const body = await res.json()
    expect(body.closed).toBe(0)
    expect(h.jqUpdateMany).not.toHaveBeenCalled()
  })

  test('does NOT close a freshly-started row inside the grace window', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date() },
    ])
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    const body = await res.json()
    expect(body.closed).toBe(0)
  })

  test('the close is guarded on status=running, so a repeat reconcile is idempotent', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) },
    ])
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    // The WHERE clause re-checks status='running', so a concurrent close (or a
    // second reconcile pass) can never double-transition the same row.
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 'j1', status: 'running' }),
    }))
  })

  test('a malformed body (activeProjects absent / not an array) is treated as no active projects', async () => {
    h.jqFindMany.mockResolvedValue([{ id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) }])
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: 'oops' }))
    expect((await res.json()).closed).toBe(1) // nothing active -> the stale row closes
  })
})

describe('reconcile route - stuck ScanJob rows (phantom "running")', () => {
  const old = () => new Date(Date.now() - 5 * 60_000)

  // The core symptom: a scheduled scan that finished with nobody viewing its project
  // leaves a 'running' ScanJob forever, and a 15-min schedule piles them up. The
  // reaper's reconcile now closes them server-side, using the orchestrator's real
  // outcome for the row (completed here).
  test('closes a stuck ScanJob using the orchestrator outcome (completed)', async () => {
    h.sweep([{ id: 's1', projectId: 'p1', kind: 'full_recon' }])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'completed' }) })
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect((await res.json()).scansClosed).toBe(1)
    expect(h.sjUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 's1', status: 'running' }),
      data: expect.objectContaining({ status: 'completed' }),
    }))
    // Queried the recon status path for this kind.
    expect(String(h.orchFetch.mock.calls[0][0])).toMatch(/\/recon\/p1\/status$/)
  })

  test('an orchestrator error maps to failed', async () => {
    h.sweep([{ id: 's1', projectId: 'p1', kind: 'gvm' }])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'error' }) })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.sjUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'failed' }),
    }))
  })

  // A scan the orchestrator has forgotten (restart, or reaped) -> we cannot confirm
  // how it ended, so 'canceled' rather than a stuck 'running'.
  test('a scan the orchestrator no longer knows about is canceled', async () => {
    h.sweep([{ id: 's1', projectId: 'p1', kind: 'full_recon' }])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'idle' }) })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.sjUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'canceled' }),
    }))
  })

  // The pile: several stuck rows for the same project+kind. The newest takes the
  // real outcome; the older, superseded runs are canceled. One status fetch per group.
  test('a pile of stuck rows: newest takes the outcome, older are canceled', async () => {
    // Route orders newest-first within a group; mirror that here.
    h.sweep([
      { id: 'newest', projectId: 'p1', kind: 'full_recon' },
      { id: 'older1', projectId: 'p1', kind: 'full_recon' },
      { id: 'older2', projectId: 'p1', kind: 'full_recon' },
    ])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'completed' }) })
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect((await res.json()).scansClosed).toBe(3)
    expect(h.orchFetch).toHaveBeenCalledTimes(1) // one fetch for the group
    const byId = Object.fromEntries(h.sjUpdateMany.mock.calls.map(c => [c[0].where.id, c[0].data.status]))
    expect(byId).toEqual({ newest: 'completed', older1: 'canceled', older2: 'canceled' })
  })

  test('a ScanJob whose project IS active is left running', async () => {
    h.sweep([{ id: 's1', projectId: 'p1', kind: 'full_recon' }])
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    expect((await res.json()).scansClosed).toBe(0)
    expect(h.sjUpdateMany).not.toHaveBeenCalled()
  })

  // Only kinds that WRITE a ScanJob per project are swept. partial_recon,
  // trufflehog and ai_attack are run-keyed (the run-granular sweep below);
  // supply_chain_repo is queue-dispatched and writes no ScanJob (its history is
  // the JobQueue row, closed by the queue reconcile).
  test('sweeps only the one-ScanJob-per-project kinds', async () => {
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    const where = h.sjFindMany.mock.calls[0][0].where
    for (const k of ['full_recon', 'supply_chain', 'gvm', 'github_hunt']) {
      expect(where.kind.in).toContain(k)
    }
    // trufflehog is run-keyed since the multi-source migration: sweeping it here
    // would force-cancel all but the newest row per (project, kind), i.e. every
    // parallel source but one, while their containers were still running.
    for (const k of ['partial_recon', 'ai_attack', 'supply_chain_repo', 'trufflehog']) {
      expect(where.kind.in).not.toContain(k)
    }
  })

  test('trufflehog rows are swept run-granularly against /all', async () => {
    h.sweep([
      { id: 'r-docker', projectId: 'p1', kind: 'trufflehog', runId: 'docker' },
      { id: 'r-hf', projectId: 'p1', kind: 'trufflehog', runId: 'huggingface' },
    ])
    h.orchFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ runs: [
        { run_id: 'docker', status: 'completed' },
        { run_id: 'huggingface', status: 'error' },
      ] }),
    })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    // Each row takes ITS OWN run's outcome; neither cancels the other.
    const byId = Object.fromEntries(h.sjUpdateMany.mock.calls.map(c => [c[0].where.id, c[0].data.status]))
    expect(byId).toEqual({ 'r-docker': 'completed', 'r-hf': 'failed' })
    expect(String(h.orchFetch.mock.calls[0][0])).toMatch(/\/trufflehog\/p1\/all$/)
  })

  test('a trufflehog row whose run vanished from /all is canceled, not left running', async () => {
    h.sweep([{ id: 'r1', projectId: 'p1', kind: 'trufflehog', runId: 'docker' }])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ runs: [] }) })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.sjUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'canceled' }),
    }))
  })

  test('one /all fetch serves every stuck run of a project', async () => {
    h.sweep([
      { id: 'a', projectId: 'p1', kind: 'trufflehog', runId: 'docker' },
      { id: 'b', projectId: 'p1', kind: 'trufflehog', runId: 's3' },
      { id: 'c', projectId: 'p1', kind: 'trufflehog', runId: 'gcs' },
    ])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ runs: [] }) })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.orchFetch).toHaveBeenCalledTimes(1)
  })

  // Active projects are excluded at the DB level, so a genuinely-running scan never
  // consumes the per-tick budget and starves the stale rows behind it.
  test('active projects are excluded in the ScanJob query, not just after', async () => {
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['pa', 'pb'] }))
    const where = h.sjFindMany.mock.calls[0][0].where
    expect(where.projectId).toEqual({ notIn: ['pa', 'pb'] })
  })

  test('with no active projects the ScanJob query carries no project filter', async () => {
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.sjFindMany.mock.calls[0][0].where.projectId).toBeUndefined()
  })
})

// L-13: a partial recon that ended with nobody watching, or was stopped, left its
// ScanJob `running` for ever: only the browser's list poll closed one, and only
// on a listed terminal status, while the orchestrator drops a finished run from
// its listing about a minute later and a stopped one at once.
describe('reconcile route - partial recon runs', () => {
  const old = () => new Date(Date.now() - 5 * 60_000)
  const listing = (runs: { run_id: string; status: string }[]) =>
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ project_id: 'p1', runs }) })
  const outcomes = () => Object.fromEntries(h.sjUpdateMany.mock.calls.map(c => [c[0].where.id, c[0].data.status]))

  test('each row is closed from its own run in /recon/<project>/partial/all', async () => {
    h.sweep([
      { id: 'done', projectId: 'p1', kind: 'partial_recon', runId: 'r1', startedAt: old() },
      { id: 'broke', projectId: 'p1', kind: 'partial_recon', runId: 'r2', startedAt: old() },
      { id: 'gone', projectId: 'p1', kind: 'partial_recon', runId: 'r3', startedAt: old() },
    ])
    listing([{ run_id: 'r1', status: 'completed' }, { run_id: 'r2', status: 'error' }])
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(outcomes()).toEqual({ done: 'completed', broke: 'failed', gone: 'canceled' })
    expect((await res.json()).scansClosed).toBe(3)
    expect(h.orchFetch).toHaveBeenCalledTimes(1)
    expect(String(h.orchFetch.mock.calls[0][0])).toMatch(/\/recon\/p1\/partial\/all$/)
    expect(h.sjUpdateMany.mock.calls[0][0].where).toMatchObject({ status: 'running' })
  })

  // A short run is dropped from the listing a minute after it ends, which can be
  // before its row is past the grace: its listed outcome is taken while it is there.
  test('a short run that already ended is closed from the listing inside the grace', async () => {
    h.sweep([{ id: 'quick', projectId: 'p1', kind: 'partial_recon', runId: 'r1', startedAt: new Date() }])
    listing([{ run_id: 'r1', status: 'completed' }])
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(outcomes()).toEqual({ quick: 'completed' })
  })

  test('a young row whose run is not listed yet waits for the grace', async () => {
    h.sweep([{ id: 'fresh', projectId: 'p1', kind: 'partial_recon', runId: 'r1', startedAt: new Date() }])
    listing([])
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(h.sjUpdateMany).not.toHaveBeenCalled()
  })

  // Partial runs go in parallel: one long run keeps the project active, which
  // must not keep its finished siblings `running` until it ends.
  test('a project with a live run still has its finished and vanished runs closed', async () => {
    h.sweep([
      { id: 'live', projectId: 'p1', kind: 'partial_recon', runId: 'r-live', startedAt: old() },
      { id: 'stopping', projectId: 'p1', kind: 'partial_recon', runId: 'r-stop', startedAt: old() },
      { id: 'done', projectId: 'p1', kind: 'partial_recon', runId: 'r-done', startedAt: old() },
      { id: 'gone', projectId: 'p1', kind: 'partial_recon', runId: 'r-gone', startedAt: old() },
    ])
    listing([
      { run_id: 'r-live', status: 'running' },
      { run_id: 'r-stop', status: 'stopping' },
      { run_id: 'r-done', status: 'completed' },
    ])
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    expect(outcomes()).toEqual({ done: 'completed', gone: 'canceled' })
  })

  test('an unreadable listing never closes a row of a project that is still active', async () => {
    h.sweep([{ id: 'x', projectId: 'p1', kind: 'partial_recon', runId: 'r1', startedAt: old() }])
    h.orchFetch.mockRejectedValue(new Error('connect ECONNREFUSED'))
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    expect(h.sjUpdateMany).not.toHaveBeenCalled()
  })

  test('a listing without a run list is unreadable, not empty', async () => {
    h.sweep([{ id: 'x', projectId: 'p1', kind: 'partial_recon', runId: 'r1', startedAt: old() }])
    h.orchFetch.mockResolvedValue({ ok: true, json: async () => ({ detail: 'nope' }) })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    expect(h.sjUpdateMany).not.toHaveBeenCalled()
  })

  // The project is known idle, so the run is over; only its outcome is unknown.
  test('an unreadable listing for an idle project records the old row canceled', async () => {
    h.sweep([{ id: 'x', projectId: 'p1', kind: 'partial_recon', runId: 'r1', startedAt: old() }])
    h.orchFetch.mockResolvedValue({ ok: false, json: async () => ({}) })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    expect(outcomes()).toEqual({ x: 'canceled' })
  })

  // AI attack used to be left to the browser's list poll, which never sees a
  // stopped run end and is gone once the tab closes.
  test('the run-keyed sweep covers partial recon, trufflehog and AI attack', async () => {
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    const runKeyed = h.sjFindMany.mock.calls.map(c => c[0].where).filter(w => w.kind.in.includes('partial_recon'))
    expect(runKeyed.length).toBeGreaterThan(0)
    for (const w of runKeyed) {
      expect(w.kind.in).toEqual(expect.arrayContaining(['partial_recon', 'trufflehog', 'ai_attack']))
    }
  })

  test('AI attack rows are closed from their own run in /ai-attack-surface/<project>/all', async () => {
    h.sweep([
      { id: 'done', projectId: 'p1', kind: 'ai_attack', runId: 'a1', startedAt: old() },
      { id: 'live', projectId: 'p1', kind: 'ai_attack', runId: 'a2', startedAt: old() },
      { id: 'gone', projectId: 'p1', kind: 'ai_attack', runId: 'a3', startedAt: old() },
    ])
    listing([{ run_id: 'a1', status: 'completed' }, { run_id: 'a2', status: 'running' }])
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    expect(outcomes()).toEqual({ done: 'completed', gone: 'canceled' })
    expect(h.orchFetch).toHaveBeenCalledTimes(1)
    expect(String(h.orchFetch.mock.calls[0][0])).toMatch(/\/ai-attack-surface\/p1\/all$/)
  })

  // A project's live runs stay out of the idle projects' budget, so they never
  // starve the stuck rows of projects that have nothing running.
  test('the idle projects are swept in a query that excludes the active ones', async () => {
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    const runKeyed = h.sjFindMany.mock.calls.map(c => c[0].where).filter(w => w.kind.in.includes('partial_recon'))
    expect(runKeyed.some(w => w.projectId?.notIn?.includes('p1'))).toBe(true)
  })
})

describe('dispatch: a job of an account that is not active (step 2.3, DV-39)', () => {
  const users = (statuses: Record<string, string>) =>
    h.userFindMany.mockImplementation(async ({ where }: { where: { id: { in: string[] } } }) =>
      where.id.in.filter((id) => id in statuses).map((id) => ({ id, status: statuses[id] })))
  const go = () => dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))

  beforeEach(async () => {
    const { setFlagsForTests } = await import('@/lib/authz/flags')
    setFlagsForTests({ identity: true })
    h.jqFindUnique.mockResolvedValue(baseRow({ userId: 'admin-acting' }))
    users({ 'admin-acting': 'active', u1: 'active' })
    vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(async () => {
    const { setFlagsForTests } = await import('@/lib/authz/flags')
    setFlagsForTests(null)
    vi.restoreAllMocks()
  })

  test('a queued job of a disabled actor is cancelled, audited, and nothing starts', async () => {
    users({ 'admin-acting': 'disabled', u1: 'active' })
    const body = await (await go()).json()
    expect(body).toEqual({ ok: false, canceled: true, blocked: 'actor_inactive', error: 'the account that queued it is disabled' })
    expect(h.dispatchStart).not.toHaveBeenCalled()
    const cancel = h.jqUpdateMany.mock.calls.find((c) => c[0].data.status === 'canceled')
    expect(cancel?.[0]).toEqual({
      where: { id: 'j1', status: 'dispatching' },
      data: {
        status: 'canceled', blockedCode: 'actor_inactive', blockedReason: 'the account that queued it is disabled',
        finishedAt: expect.any(Date),
      },
    })
    expect(h.audit).toHaveBeenCalledWith({
      actorId: null, action: 'job_queue.cancelled', targetType: 'jobQueue', targetId: 'j1',
      after: {
        reason: 'actor_inactive', projectId: 'p1', kind: 'full_recon',
        userId: 'admin-acting', account: 'actor', status: 'disabled',
      },
      source: 'system',
    })
  })

  test("a disabled project owner cancels the job too, judged on the project already read", async () => {
    users({ 'admin-acting': 'active', u1: 'disabled' })
    const body = await (await go()).json()
    expect(body).toMatchObject({ canceled: true, error: "the project owner's account is disabled" })
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.projectFindUnique).toHaveBeenCalledTimes(1)
    expect(h.userFindMany.mock.calls[0][0]).toEqual({ where: { id: { in: ['admin-acting', 'u1'] } }, select: { id: true, status: true } })
  })

  test('active accounts: the job starts as before, for the account that queued it', async () => {
    expect((await (await go()).json()).ok).toBe(true)
    expect(h.dispatchStart).toHaveBeenCalledWith('full_recon', 'p1', { actorUserId: 'admin-acting', payload: {} })
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('a deleted project still fails as before, without reading accounts', async () => {
    h.projectFindUnique.mockResolvedValue(null)
    expect((await (await go()).json()).error).toBe('project no longer exists')
    expect(h.userFindMany).not.toHaveBeenCalled()
  })

  test("switch off → today's behaviour: no account read, the job starts", async () => {
    const { setFlagsForTests } = await import('@/lib/authz/flags')
    setFlagsForTests({ identity: false })
    users({ 'admin-acting': 'disabled', u1: 'disabled' })
    expect((await (await go()).json()).ok).toBe(true)
    expect(h.dispatchStart).toHaveBeenCalled()
    expect(h.userFindMany).not.toHaveBeenCalled()
  })
})

describe('dispatch: a job whose actor lost access to the project (step 5.5, DV-38)', () => {
  const go = () => dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
  const LOST = { userId: 'collab-1', permission: 'scan:gvm', reason: 'project_not_visible' }

  beforeEach(() => {
    h.jqFindUnique.mockResolvedValue(baseRow({ userId: 'collab-1', kind: 'gvm' }))
    vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => vi.restoreAllMocks())

  test('dispatch cancels a job whose actor lost access: audited, logged, nothing starts', async () => {
    h.actorRefusal.mockResolvedValue(LOST)
    const body = await (await go()).json()
    expect(body).toEqual({
      ok: false, canceled: true, blocked: 'actor_no_access',
      error: 'the account that queued it no longer has access to this project',
    })
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.actorRefusal).toHaveBeenCalledWith('collab-1', 'p1', ['scan:gvm'])
    const cancel = h.jqUpdateMany.mock.calls.find((c) => c[0].data.status === 'canceled')
    expect(cancel?.[0]).toEqual({
      where: { id: 'j1', status: 'dispatching' },
      data: {
        status: 'canceled', blockedCode: 'actor_no_access',
        blockedReason: 'the account that queued it no longer has access to this project', finishedAt: expect.any(Date),
      },
    })
    expect(h.audit).toHaveBeenCalledWith({
      actorId: null, projectId: 'p1', action: 'job_queue.cancelled', targetType: 'jobQueue', targetId: 'j1',
      after: {
        reason: 'actor_no_access', projectId: 'p1', kind: 'gvm',
        userId: 'collab-1', permission: 'scan:gvm', refusal: 'project_not_visible',
      },
      source: 'system',
    })
    expect(console.warn).toHaveBeenCalledWith('[rbac] job j1 cancelled: actor collab-1 lost scan:gvm on project p1 (project_not_visible)')
  })

  test('the check asks the permissions of the job, overwrite included', async () => {
    h.jqFindUnique.mockResolvedValue(baseRow({ userId: 'collab-1', kind: 'full_recon', payload: { mode: 'overwrite' } }))
    await go()
    expect(h.actorRefusal).toHaveBeenCalledWith('collab-1', 'p1', ['recon:scan', 'recon:overwrite'])
    h.jqFindUnique.mockResolvedValue(baseRow({ userId: 'collab-1', kind: 'partial_recon', payload: {} }))
    h.actorRefusal.mockClear()
    await go()
    expect(h.actorRefusal).toHaveBeenCalledWith('collab-1', 'p1', ['recon:partial'])
  })

  test("an owner's job passes and starts as before (owner unchanged)", async () => {
    h.jqFindUnique.mockResolvedValue(baseRow())
    expect((await (await go()).json()).ok).toBe(true)
    expect(h.actorRefusal).toHaveBeenCalledWith('u1', 'p1', ['recon:scan'])
    expect(h.dispatchStart).toHaveBeenCalledWith('full_recon', 'p1', { actorUserId: 'u1', payload: {} })
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('an access check that cannot be read starts nothing and spends an attempt (never)', async () => {
    h.actorRefusal.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await go()
    expect(res.status).toBe(500)
    expect(h.dispatchStart).not.toHaveBeenCalled()
    const retry = h.jqUpdateMany.mock.calls.find((c) => c[0].data.status === 'queued')
    expect(retry?.[0].data).toMatchObject({ status: 'queued', attempts: 1, blockedCode: 'transient' })
  })

  test('a deleted project fails before any access check', async () => {
    h.projectFindUnique.mockResolvedValue(null)
    expect((await (await go()).json()).error).toBe('project no longer exists')
    expect(h.actorRefusal).not.toHaveBeenCalled()
  })
})
