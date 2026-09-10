/**
 * The shared full-scan start path (Sections 3 + 7.2).
 *
 * Manual and scheduled scans both go through here, so this is where the
 * load-bearing behavior is pinned: the activation lock, freeze-before-start
 * (fail closed), `mode` passthrough, and the ScanJob history for every outcome.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  orchestratorFetch: vi.fn(),
  isActivating: vi.fn(),
  busy: vi.fn(),
  prepare: vi.fn(),
  createJob: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => h.findProject(...a) } },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: (...a: unknown[]) => h.isActivating(...a) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: (...a: unknown[]) => h.busy(...a) }))
vi.mock('@/lib/scanTimeline', async orig => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  prepareVersionsForFullScan: (...a: unknown[]) => h.prepare(...a),
  createScanJob: (...a: unknown[]) => h.createJob(...a),
}))

import { startFullScan } from './startFullScan'
import { SnapshotFreezeError } from './scanTimeline'

const orchestratorBody = () => JSON.parse(h.orchestratorFetch.mock.calls[0][1].body)

beforeEach(() => {
  vi.clearAllMocks()
  h.isActivating.mockResolvedValue(false)
  h.busy.mockResolvedValue(null)
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', targetDomain: 'x.tld', ipMode: false, targetIps: [] })
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ project_id: 'p1', status: 'starting' }) })
  h.prepare.mockResolvedValue({
    currentVersion: { id: 'v3', seq: 3, label: 'Scan 3' },
    frozenVersionId: 'v2',
    frozenNodeCount: 120,
  })
  h.createJob.mockResolvedValue({ id: 'job1' })
})

describe('activation lock (4A.3)', () => {
  test('refuses while the graph is being swapped, before any freeze or spawn', async () => {
    h.isActivating.mockResolvedValue(true)
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(false)
    if (res.ok) throw new Error('unreachable')
    expect(res.status).toBe(409)
    expect(res.activationInProgress).toBe(true)
    expect(h.prepare).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

describe('Risk 1: never snapshot a mid-write graph', () => {
  test('a scan already running is rejected BEFORE the freeze, with no version churn', async () => {
    // The orchestrator would reject the duplicate start anyway, but by then we
    // would have captured a snapshot of a graph the running scan is rewriting
    // AND minted a version for a scan that never happens.
    h.busy.mockResolvedValue('a full recon scan is running')
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(false)
    if (res.ok) throw new Error('unreachable')
    expect(res.status).toBe(409)
    expect(res.error).toMatch(/already running|scan is running/i)
    expect(h.prepare).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('an active partial recon also blocks the freeze', async () => {
    h.busy.mockResolvedValue('a partial recon run is active')
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 409 })
    expect(h.prepare).not.toHaveBeenCalled()
  })

  test('a running AGENT session does not block a scan (unchanged behavior)', async () => {
    // Agents legitimately run while a scan runs; only the graph-swapping
    // activation is mutually exclusive with them.
    h.busy.mockResolvedValue(null)
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(true)
  })
})

describe('preconditions', () => {
  test('unknown project → 404 before any version work', async () => {
    h.findProject.mockResolvedValue(null)
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 404 })
    expect(h.prepare).not.toHaveBeenCalled()
  })

  test('no target configured → 400 before any version work', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', targetDomain: '', ipMode: false, targetIps: [] })
    expect(await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .toMatchObject({ ok: false, status: 400 })
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', targetDomain: '', ipMode: true, targetIps: [] })
    expect(await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .toMatchObject({ ok: false, status: 400 })
    expect(h.prepare).not.toHaveBeenCalled()
  })
})

describe('freeze ordering and fail-closed', () => {
  test('the freeze happens BEFORE the orchestrator is asked to start', async () => {
    const order: string[] = []
    h.prepare.mockImplementation(async () => {
      order.push('freeze')
      return { currentVersion: { id: 'v3', seq: 3, label: 'Scan 3' }, frozenVersionId: 'v2', frozenNodeCount: 1 }
    })
    h.orchestratorFetch.mockImplementation(async () => {
      order.push('start')
      return { ok: true, json: async () => ({}) }
    })
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(order).toEqual(['freeze', 'start'])
  })

  test('a freeze failure aborts: no scan started, no job row (Risk 4)', async () => {
    h.prepare.mockRejectedValue(new SnapshotFreezeError('Could not snapshot the current graph'))
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 500, snapshotFailed: true })
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(h.createJob).not.toHaveBeenCalled()
  })

  test('an unexpected error is not swallowed as a "snapshot failed"', async () => {
    h.prepare.mockRejectedValue(new Error('programming error'))
    await expect(startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .rejects.toThrow('programming error')
  })
})

describe('mode + trigger', () => {
  test.each(['new', 'overwrite'] as const)('mode %s is forwarded to the orchestrator', async mode => {
    await startFullScan({ projectId: 'p1', mode, trigger: 'manual' })
    expect(h.prepare).toHaveBeenCalledWith('p1', mode, null)
    expect(orchestratorBody().mode).toBe(mode)
  })

  test('a scheduled run records trigger + scheduleId on the job', async () => {
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', scheduleId: 's1', actorUserId: 'u1' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({
      trigger: 'scheduled', scheduleId: 's1', status: 'running', initiatedByUserId: 'u1',
    }))
  })
})

describe('history for every outcome', () => {
  test('success records a running job against the new current version', async () => {
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual', actorUserId: 'u1' })
    expect(res).toMatchObject({ ok: true, versionId: 'v3', frozenVersionId: 'v2', scanJobId: 'job1' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({
      projectId: 'p1', versionId: 'v3', status: 'running',
    }))
  })

  test('a RAM rejection is recorded as deferred_ram with its reason', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 429,
      json: async () => ({ detail: { limitType: 'ram', detail: 'Not enough free memory' } }),
    })
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', scheduleId: 's1' })
    expect(res).toMatchObject({ ok: false, status: 429 })
    if (res.ok) throw new Error('unreachable')
    expect(res.limit).toMatchObject({ limitType: 'ram' })
    expect(res.error).toMatch(/RAM limit/)
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({
      status: 'deferred_ram', ramReason: 'Not enough free memory', scheduleId: 's1',
    }))
  })

  test('a configured (hard) limit is recorded as failed, not deferred', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 429,
      json: async () => ({ detail: { limitType: 'hard', detail: '2 of 2 concurrent scans allowed', settingName: 'RECON_MAX_CONCURRENT_GLOBAL' } }),
    })
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    if (res.ok) throw new Error('unreachable')
    expect(res.error).toMatch(/configured limit/)
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed' }))
  })

  test('a plain rejection (e.g. RoE window) is recorded as failed and surfaced verbatim', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 403, json: async () => ({ detail: 'Outside the RoE time window' }),
    })
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', scheduleId: 's1' })
    expect(res).toMatchObject({ ok: false, status: 403, error: 'Outside the RoE time window' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed' }))
  })

  test('a job-write failure does not fail the start (history is best-effort)', async () => {
    h.createJob.mockRejectedValue(new Error('db down'))
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(true)
    if (!res.ok) throw new Error('unreachable')
    expect(res.scanJobId).toBeNull()
  })
})

// Strategy row 1: a Domain-batch project must be able to start a scan.
// Its scope lives in domainBatchGroups, not targetDomain (which is empty), so the
// single-domain precondition would have refused every batch scan outright.
describe('domain batch preconditions', () => {
  const batchProject = (groups: unknown) => ({
    id: 'p1', userId: 'owner', targetDomain: '', ipMode: false, targetIps: [],
    domainBatchMode: true, domainBatchGroups: groups,
  })

  test('a batch with groups starts and reaches the orchestrator', async () => {
    h.findProject.mockResolvedValue(batchProject([
      { rootDomain: 'domain1.com', prefixes: ['sub1.'] },
      { rootDomain: 'domain2.it', prefixes: ['sub2.'] },
    ]))
    const r = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })

    expect(r.ok).toBe(true)
    expect(h.orchestratorFetch).toHaveBeenCalledOnce()
    expect(orchestratorBody().project_id).toBe('p1')
  })

  test('an empty group list is refused with 400 and never starts a container', async () => {
    h.findProject.mockResolvedValue(batchProject([]))
    const r = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })

    expect(r.ok).toBe(false)
    expect((r as { status: number }).status).toBe(400)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('a null group list (never saved) is refused, not treated as no-op', async () => {
    h.findProject.mockResolvedValue(batchProject(null))
    const r = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })

    expect(r.ok).toBe(false)
    expect((r as { status: number }).status).toBe(400)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('a batch is not held to the single-domain targetDomain requirement', async () => {
    h.findProject.mockResolvedValue(batchProject([{ rootDomain: 'a.com', prefixes: ['.'] }]))
    const r = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })

    expect(r.ok).toBe(true)
    if (!r.ok) expect(r.error).not.toContain('no target domain')
  })

  test('a non-batch project with no target still fails as before', async () => {
    h.findProject.mockResolvedValue({
      id: 'p1', userId: 'owner', targetDomain: '', ipMode: false, targetIps: [],
      domainBatchMode: false, domainBatchGroups: null,
    })
    const r = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })

    expect(r.ok).toBe(false)
    expect((r as { error: string }).error).toContain('no target domain')
  })
})
