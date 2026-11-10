/**
 * Scan Queue - Activity view API (Phase 5): system/jobs (tenancy), cancel +
 * reconfirm (object-level authz via projectId re-resolved from the row).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { settingsFingerprint } from '@/lib/jobQueue'
import { authProfileFingerprint } from '@/lib/authProfileFingerprint'

const h = vi.hoisted(() => ({
  effectiveUser: vi.fn(),
  guardProject: vi.fn(),
  jqFindUnique: vi.fn(),
  jqFindMany: vi.fn(),
  jqUpdate: vi.fn(),
  jqUpdateMany: vi.fn(),
  jqGroupBy: vi.fn(),
  jqCount: vi.fn(),
  sjFindMany: vi.fn(),
  sjCount: vi.fn(),
  projectFindMany: vi.fn(),
  projectFindUnique: vi.fn(),
  authProfileFindUnique: vi.fn(),
  orchestratorFetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    jobQueue: {
      findUnique: (...a: unknown[]) => h.jqFindUnique(...a),
      findMany: (...a: unknown[]) => h.jqFindMany(...a),
      update: (...a: unknown[]) => h.jqUpdate(...a),
      updateMany: (...a: unknown[]) => h.jqUpdateMany(...a),
      groupBy: (...a: unknown[]) => h.jqGroupBy(...a),
      count: (...a: unknown[]) => h.jqCount(...a),
    },
    scanJob: {
      findMany: (...a: unknown[]) => h.sjFindMany(...a),
      count: (...a: unknown[]) => h.sjCount(...a),
    },
    project: {
      findUnique: (...a: unknown[]) => h.projectFindUnique(...a),
      findMany: (...a: unknown[]) => h.projectFindMany(...a),
    },
    projectAuthProfile: { findUnique: (...a: unknown[]) => h.authProfileFindUnique(...a) },
  },
}))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.effectiveUser(),
  guardProject: (...a: unknown[]) => h.guardProject(...a),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))

import { GET as systemJobs } from './route'
import { POST as cancel } from '../../job-queue/[id]/cancel/route'
import { POST as reconfirm } from '../../job-queue/[id]/reconfirm/route'

const PROJECT = {
  id: 'p1', targetDomain: 'example.com', ipMode: false, targetIps: [],
  scanModules: ['port_scan'], targetGuardrailEnabled: true, stealthMode: false,
}

/** A JobQueue row as the route's `select` returns it. */
const qRow = (over: Record<string, unknown>) => ({
  id: 'j', projectId: 'p1', kind: 'gvm', status: 'queued', priority: 0, attempts: 0,
  blockedCode: '', blockedReason: '', error: '', envelopeBytes: BigInt(2147483648),
  enqueuedAt: new Date(), startedAt: null, finishedAt: null, scanJobId: null, runId: '',
  project: { name: 'Proj One' },
  ...over,
})

/** A ScanJob row as the route's `select` returns it. Every kind writes one now. */
const sjRow = (over: Record<string, unknown>) => ({
  id: 's', projectId: 'p1', kind: 'full_recon', runId: '',
  startedAt: new Date(), createdAt: new Date(), project: { name: 'Proj One' },
  ...over,
})

/** Mutable per-test payload for GET /system/active-scans. */
let liveScans: Record<string, unknown>[] = []

const live = (over: Record<string, unknown> = {}) => ({
  kind: 'gvm', project_id: 'p1', run_id: '', tool_id: '',
  status: 'running', started_at: '2026-08-09T21:00:00.000Z',
  ...over,
})

const req = () => new NextRequest('http://x')
const sp = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  liveScans = []
  h.effectiveUser.mockResolvedValue({ userId: 'u1' })
  h.guardProject.mockResolvedValue(null) // access allowed
  h.jqUpdate.mockResolvedValue({})
  h.jqUpdateMany.mockResolvedValue({ count: 1 })
  h.sjFindMany.mockResolvedValue([])
  h.sjCount.mockResolvedValue(0)
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.projectFindMany.mockResolvedValue([{ id: 'p1', name: 'Proj One' }])
  // Two different orchestrator reads share this mock; route them by URL.
  h.orchestratorFetch.mockImplementation((url: string) =>
    Promise.resolve(String(url).includes('/system/active-scans')
      ? { ok: true, json: async () => ({ scans: liveScans }) }
      : { ok: true, json: async () => ({ remaining_for_new: 123 }) }))
})

describe('GET /api/system/jobs', () => {
  test('splits own rows by state and aggregates others', async () => {
    h.jqFindMany.mockImplementation((args: { where: { status: { in: string[] } } }) => {
      if (args.where.status.in.includes('running')) {
        return Promise.resolve([
          qRow({ id: 'a', kind: 'full_recon', status: 'running', priority: 10, startedAt: new Date() }),
          qRow({ id: 'b', kind: 'gvm', status: 'queued', attempts: 1, blockedCode: 'ram', blockedReason: 'no mem', envelopeBytes: BigInt(2684354560) }),
          qRow({ id: 'c', kind: 'trufflehog', status: 'needs_review', blockedCode: 'settings_changed', blockedReason: 'changed', envelopeBytes: BigInt(805306368) }),
        ])
      }
      return Promise.resolve([]) // recent
    })
    h.jqGroupBy.mockResolvedValue([
      { status: 'queued', kind: 'gvm', projectId: 'zz', _count: { _all: 3 } },
      { status: 'running', kind: 'gvm', projectId: 'zz', _count: { _all: 1 } },
    ])
    h.jqCount.mockResolvedValue(2)

    const res = await systemJobs(req())
    const body = await res.json()
    expect(body.mine.running).toHaveLength(1)
    expect(body.mine.queued).toHaveLength(1)
    expect(body.mine.queued[0]).toMatchObject({ blockedReason: 'no mem', envelopeBytes: 2684354560 })
    expect(body.mine.queued[0]).toMatchObject({ projectName: 'Proj One', source: 'queue' })
    expect(body.mine.needsReview).toHaveLength(1)
    expect(body.others).toMatchObject({ queued: 3, running: 1, needsReview: 2 })
    expect(body.ledger).toMatchObject({ remaining_for_new: 123 })
  })

  // A scan started straight from the Start button has no JobQueue row at all; before
  // this it left the panel reading "Running 0" while recon containers were up.
  test('a running scan with no queue row is listed as running', async () => {
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.sjFindMany.mockResolvedValue([
      sjRow({ id: 's1', projectId: 'p1', project: { name: 'Proj One' } }),
      sjRow({ id: 's2', projectId: 'p2', project: { name: 'Proj Two' } }),
    ])

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running).toHaveLength(2)
    expect(body.mine.running.map((r: { projectName: string }) => r.projectName)).toEqual(['Proj One', 'Proj Two'])
    expect(body.mine.running[0]).toMatchObject({ kind: 'full_recon', status: 'running', source: 'scan' })
  })

  test('a scan the queue dispatched is listed once, from its queue row', async () => {
    h.jqFindMany.mockImplementation((args: { where: { status: { in: string[] } } }) =>
      Promise.resolve(args.where.status.in.includes('running')
        ? [qRow({ id: 'a', kind: 'full_recon', status: 'running', scanJobId: 's1', startedAt: new Date() })]
        : []))
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.sjFindMany.mockResolvedValue([
      sjRow({ id: 's1', projectId: 'p1' }),
    ])

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running).toHaveLength(1)
    expect(body.mine.running[0]).toMatchObject({ id: 'a', source: 'queue' })
  })

  test("another user's dispatched full recon is not counted twice", async () => {
    h.jqFindMany.mockResolvedValue([])
    // Their running full_recon queue row and its ScanJob are the same scan.
    h.jqGroupBy.mockResolvedValue([{ status: 'running', kind: 'full_recon', projectId: 'zz', scanJobId: 's1', _count: { _all: 1 } }])
    h.jqCount.mockResolvedValue(0)
    h.sjCount.mockResolvedValue(1)

    const body = await (await systemJobs(req())).json()
    expect(body.others.running).toBe(1)
  })

  // Every queue-dispatched kind but supply_chain_repo records a ScanJob too
  // (L-12), so a queue row counts only while no ScanJob stands for its scan.
  describe("another user's in-flight work counts each scan once", () => {
    const others = async (groups: Record<string, unknown>[], scanJobs: number) => {
      h.jqFindMany.mockResolvedValue([])
      h.jqGroupBy.mockResolvedValue(groups.map(g => ({ projectId: 'zz', _count: { _all: 1 }, ...g })))
      h.jqCount.mockResolvedValue(0)
      h.sjCount.mockResolvedValue(scanJobs)
      return (await (await systemJobs(req())).json()).others
    }

    test('the query groups the queue rows by the ScanJob they started', async () => {
      await others([], 0)
      const args = h.jqGroupBy.mock.calls[0][0]
      expect(args.by).toEqual(expect.arrayContaining(['status', 'scanJobId']))
    })

    test.each(['gvm', 'partial_recon', 'ai_attack', 'trufflehog', 'github_hunt', 'supply_chain'])(
      'a queue-dispatched %s and its ScanJob are one scan', async kind => {
        expect((await others([{ status: 'running', kind, scanJobId: 'sj9' }], 1)).running).toBe(1)
      })

    test('a dispatching job has no ScanJob yet and is counted, a full recon too', async () => {
      const o = await others([
        { status: 'dispatching', kind: 'full_recon', scanJobId: null },
        { status: 'dispatching', kind: 'gvm', scanJobId: null },
      ], 0)
      expect(o.running).toBe(2)
    })

    test('a running supply_chain_repo writes no ScanJob and is counted from its queue row', async () => {
      expect((await others([{ status: 'running', kind: 'supply_chain_repo', scanJobId: null }], 0)).running).toBe(1)
    })

    test('a running queue row whose ScanJob could not be written is still counted', async () => {
      expect((await others([{ status: 'running', kind: 'gvm', scanJobId: null }], 0)).running).toBe(1)
    })

    test('queued rows stay in the queued count', async () => {
      expect(await others([{ status: 'queued', kind: 'gvm', scanJobId: null }], 0))
        .toMatchObject({ queued: 1, running: 0 })
    })
  })

  // The third source. GVM / TruffleHog / supply-chain / AI-attack write neither a
  // ScanJob nor (unless queued) a JobQueue row, so without this they ran invisibly.
  test('a live orchestrator scan of any kind is listed as running', async () => {
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    liveScans = [
      live({ kind: 'gvm' }),
      live({ kind: 'trufflehog', status: 'starting' }),
      live({ kind: 'partial_recon', run_id: 'r1', tool_id: 'katana' }),
    ]

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running.map((r: { kind: string }) => r.kind))
      .toEqual(['gvm', 'trufflehog', 'partial_recon'])
    expect(body.mine.running[0]).toMatchObject({ source: 'live', projectName: 'Proj One' })
    // The tool identifies one partial-recon run among several in a project.
    expect(body.mine.running[2]).toMatchObject({ detail: 'katana' })
  })

  test('a live scan already covered by its queue row is not duplicated', async () => {
    h.jqFindMany.mockImplementation((args: { where: { status: { in: string[] } } }) =>
      Promise.resolve(args.where.status.in.includes('running')
        ? [qRow({ id: 'a', kind: 'gvm', status: 'running' })]
        : []))
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    liveScans = [live({ kind: 'gvm' })]

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running).toHaveLength(1)
    expect(body.mine.running[0]).toMatchObject({ id: 'a', source: 'queue' })
  })

  test('a live scan is not duplicated while its queue row has no run id yet', async () => {
    h.jqFindMany.mockImplementation((args: { where: { status: { in: string[] } } }) =>
      Promise.resolve(args.where.status.in.includes('running')
        ? [qRow({ id: 'a', kind: 'partial_recon', status: 'dispatching', runId: '' })]
        : []))
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    liveScans = [live({ kind: 'partial_recon', run_id: 'r1' })]

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running).toHaveLength(1)
  })

  // The suppression above must not swallow a genuinely separate concurrent run:
  // one queue row without a run id absorbs exactly one live entry, not all of them.
  test('a second concurrent partial recon in the same project still shows', async () => {
    h.jqFindMany.mockImplementation((args: { where: { status: { in: string[] } } }) =>
      Promise.resolve(args.where.status.in.includes('running')
        ? [qRow({ id: 'a', kind: 'partial_recon', status: 'dispatching', runId: '' })]
        : []))
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    liveScans = [
      live({ kind: 'partial_recon', run_id: 'r1', tool_id: 'katana' }),
      live({ kind: 'partial_recon', run_id: 'r2', tool_id: 'gau' }),
    ]

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running).toHaveLength(2)
    expect(body.mine.running[1]).toMatchObject({ source: 'live', detail: 'gau' })
  })

  test('a live full recon already listed from its ScanJob is not duplicated', async () => {
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.sjFindMany.mockResolvedValue([
      sjRow({ id: 's1', projectId: 'p1' }),
    ])
    liveScans = [live({ kind: 'full_recon' })]

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running).toHaveLength(1)
    expect(body.mine.running[0]).toMatchObject({ source: 'scan' })
  })

  // Phantom filter: a scan that stopped with nobody viewing its project leaves a
  // 'running' ScanJob that only a per-project poll would close. The live set is
  // authoritative here (it has another scan), and this old ScanJob is not in it.
  test('a stale ScanJob absent from a non-empty live set is not shown as running', async () => {
    const old = new Date(Date.now() - 10 * 60_000)
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.sjFindMany.mockResolvedValue([
      sjRow({ id: 'live1', projectId: 'p1', startedAt: old }),   // really running (in live)
      sjRow({ id: 'stale1', projectId: 'p9', startedAt: old, project: { name: 'Gone' } }), // stopped, phantom
    ])
    liveScans = [live({ kind: 'full_recon', project_id: 'p1', started_at: old.toISOString() })]

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running.map((r: { projectName: string }) => r.projectName)).toEqual(['Proj One'])
  })

  // Restart-safe: when the live set is EMPTY (orchestrator just restarted, or truly
  // nothing running) we cannot tell a phantom from a real orphaned scan, so we keep
  // the ScanJob rather than hide a scan that is actually running.
  test('an empty live set never hides a running ScanJob (restart-safe)', async () => {
    const old = new Date(Date.now() - 10 * 60_000)
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.sjFindMany.mockResolvedValue([sjRow({ id: 's1', projectId: 'p1', startedAt: old })])
    liveScans = []   // fetch failed OR nothing tracked

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running).toHaveLength(1)
    expect(body.mine.running[0]).toMatchObject({ source: 'scan' })
  })

  // A scan that JUST started may not be in the orchestrator's live set yet; the
  // start grace keeps it visible so it never flickers out right after launch.
  test('a freshly-started ScanJob not yet in the live set is still shown (start grace)', async () => {
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.sjFindMany.mockResolvedValue([sjRow({ id: 'fresh', projectId: 'p1', startedAt: new Date() })])
    liveScans = [live({ kind: 'gvm', project_id: 'p2' })]   // authoritative, but not our fresh scan

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running.some((r: { id: string }) => r.id === 'fresh')).toBe(true)
  })

  // A per-repo org-batch scan runs in the same container the orchestrator reports
  // as kind 'supply_chain', so without kind-normalization the one running scan
  // would show twice: its 'supply_chain_repo' queue row AND a 'supply_chain' live
  // entry. The queue row (cancellable) must win; the live duplicate is suppressed.
  test('a supply_chain_repo queue row dedups against the supply_chain live entry', async () => {
    h.jqFindMany.mockImplementation((args: { where: { status: { in: string[] } } }) =>
      Promise.resolve(args.where.status.in.includes('running')
        ? [qRow({ id: 'r1', kind: 'supply_chain_repo', status: 'running', projectId: 'p1' })]
        : []))
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    liveScans = [live({ kind: 'supply_chain', project_id: 'p1' })]

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running).toHaveLength(1)
    expect(body.mine.running[0]).toMatchObject({ kind: 'supply_chain_repo', source: 'queue' })
  })

  // Others are counted from the DB, never from the live list: without per-project
  // rows there is no key to de-duplicate a live entry against, and every scan now
  // writes either a ScanJob or a queue row anyway.
  test("a live scan in someone else's project is never listed as mine", async () => {
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.sjCount.mockResolvedValue(1) // their ScanJob is what the count comes from
    liveScans = [live({ kind: 'gvm', project_id: 'notMine' })]

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running).toHaveLength(0)
    expect(body.others.running).toBe(1)
  })

  test("another user's queued-then-dispatched gvm is counted once, not twice", async () => {
    h.jqFindMany.mockResolvedValue([])
    // A queue-dispatched gvm has a queue row and its ScanJob, counted once, and the
    // live entry for it must not add a second.
    h.jqGroupBy.mockResolvedValue([{ status: 'running', kind: 'gvm', projectId: 'notMine', scanJobId: 'sj-gvm', _count: { _all: 1 } }])
    h.jqCount.mockResolvedValue(0)
    h.sjCount.mockResolvedValue(1)
    liveScans = [live({ kind: 'gvm', project_id: 'notMine' })]

    const body = await (await systemJobs(req())).json()
    expect(body.others.running).toBe(1)
  })

  // ScanJob is no longer full-recon-only, so the row's own kind must reach the UI.
  test('a directly-started scan of any kind is listed with its own kind', async () => {
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.sjFindMany.mockResolvedValue([
      sjRow({ id: 's1', kind: 'supply_chain' }),
      sjRow({ id: 's2', kind: 'partial_recon', runId: 'r1' }),
    ])

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running.map((r: { kind: string }) => r.kind)).toEqual(['supply_chain', 'partial_recon'])
    expect(body.mine.running[0]).toMatchObject({ source: 'scan' })
  })

  test('a live entry for a run already recorded as a ScanJob is not duplicated', async () => {
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.sjFindMany.mockResolvedValue([sjRow({ id: 's1', kind: 'partial_recon', runId: 'r1' })])
    liveScans = [live({ kind: 'partial_recon', run_id: 'r1' })]

    const body = await (await systemJobs(req())).json()
    expect(body.mine.running).toHaveLength(1)
    expect(body.mine.running[0]).toMatchObject({ source: 'scan' })
  })

  test('renders even when the orchestrator is unreachable', async () => {
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.orchestratorFetch.mockRejectedValue(new Error('down'))
    const res = await systemJobs(req())
    expect((await res.json()).ledger).toBeNull()
  })
})

describe('POST cancel', () => {
  test('a missing row is a 404', async () => {
    h.jqFindUnique.mockResolvedValue(null)
    const res = await cancel(req(), sp('x'))
    expect(res.status).toBe(404)
  })

  test('non-ownership yields the guard response (404), never a cancel', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p2', status: 'queued' })
    h.guardProject.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await cancel(req(), sp('j1'))
    expect(res.status).toBe(404)
    expect(h.jqUpdateMany).not.toHaveBeenCalled()
  })

  test('a queued row is canceled', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p1', status: 'queued' })
    const res = await cancel(req(), sp('j1'))
    expect((await res.json()).ok).toBe(true)
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'canceled' }),
    }))
  })

  test('a running row cannot be canceled (409)', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p1', status: 'running' })
    const res = await cancel(req(), sp('j1'))
    expect(res.status).toBe(409)
    expect(h.jqUpdateMany).not.toHaveBeenCalled()
  })
})

describe('POST reconfirm', () => {
  /** What the dispatcher will recompute when it picks the row up. */
  const dispatcherHash = (profile: Parameters<typeof authProfileFingerprint>[0]) =>
    settingsFingerprint('full_recon', PROJECT as unknown as Record<string, unknown>, {
      authProfileFp: authProfileFingerprint(profile),
    })

  test('a needs_review row is requeued with a freshly recomputed fingerprint', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p1', kind: 'full_recon', status: 'needs_review' })
    const res = await reconfirm(req(), sp('j1'))
    expect((await res.json()).ok).toBe(true)
    expect(h.jqUpdate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        status: 'queued',
        settingsHash: dispatcherHash(null),
        blockedCode: '',
      }),
    }))
  })

  // REGRESSION: needs_review was a state with no exit. reconfirm recomputed the
  // fingerprint from the TruffleHog extra alone, while BOTH enqueue and dispatch
  // also fold in the auth profile - a relation the Project-row fingerprint
  // cannot see, and non-empty for full_recon and partial_recon. So the
  // re-confirmed row stored a hash the dispatcher would never reproduce: it
  // dispatched, failed the comparison, and returned to needs_review forever. No
  // UI could recover it, and no MCP tool exposes reconfirm.
  //
  // The old test could not catch this: with no projectAuthProfile in the prisma
  // mock the lookup threw, authProfileFingerprintExtra swallowed it, and both
  // sides degraded to {} together.
  test('REGRESSION: a re-confirmed job stores the hash the DISPATCHER recomputes', async () => {
    const profile = {
      authType: 'header', authHeaderName: 'Authorization', authValue: 'Bearer s3cret',
      extraHeaders: { 'X-Env': 'staging' }, scopeHosts: ['example.com'], reconEnabled: true,
    }
    h.authProfileFindUnique.mockResolvedValue(profile)
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p1', kind: 'full_recon', status: 'needs_review' })

    await reconfirm(req(), sp('j1'))

    const stored = h.jqUpdate.mock.calls[0][0].data.settingsHash
    expect(stored).toBe(dispatcherHash(profile))
    // And it is genuinely profile-dependent, so the assertion above is not
    // passing because both sides happen to ignore the profile.
    expect(stored).not.toBe(dispatcherHash(null))
  })

  test('a non-needs_review row is a 409', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p1', kind: 'full_recon', status: 'queued' })
    const res = await reconfirm(req(), sp('j1'))
    expect(res.status).toBe(409)
    expect(h.jqUpdate).not.toHaveBeenCalled()
  })

  test('non-ownership yields 404', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p2', kind: 'full_recon', status: 'needs_review' })
    h.guardProject.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await reconfirm(req(), sp('j1'))
    expect(res.status).toBe(404)
  })
})

describe('failures answer a fixed sentence and a code, never the exception text', () => {
  const withCode = (message: string, code: string) => Object.assign(new Error(message), { code })
  beforeEach(() => { vi.spyOn(console, 'error').mockImplementation(() => {}) })

  test('the activity list', async () => {
    h.jqFindMany.mockRejectedValue(withCode('Timed out fetching a new connection (job_queue for u1)', 'P2024'))
    const res = await systemJobs(req())
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not load scan activity', code: 'P2024' })
  })

  test('a session read that throws is readable, not an empty 500', async () => {
    h.effectiveUser.mockRejectedValue(withCode('session store down', 'ECONNREFUSED'))
    const res = await systemJobs(req())
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not load scan activity', code: 'ECONNREFUSED' })
  })

  test('cancel and re-confirm', async () => {
    h.jqFindUnique.mockRejectedValue(withCode("Can't reach database server at db:5432", 'P1001'))
    expect(await (await cancel(req(), sp('j1'))).json()).toEqual({ error: 'Could not cancel the job', code: 'P1001' })
    expect(await (await reconfirm(req(), sp('j1'))).json()).toEqual({ error: 'Could not re-confirm the job', code: 'P1001' })
  })
})
