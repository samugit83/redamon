/**
 * Scan Timeline — full-scan version bookkeeping unit tests.
 *
 * The critical guarantee under test is FAIL CLOSED: in 'new' mode, if the current
 * graph cannot be frozen, prepareVersionsForFullScan must throw and must NOT have
 * demoted the current version or created a new one — the caller then aborts the
 * scan, so the graph is never destroyed unsaved.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const prismaMock = vi.hoisted(() => ({
  scanVersion: {
    update: vi.fn(), updateMany: vi.fn(), create: vi.fn(), findFirst: vi.fn(), findUnique: vi.fn(),
    delete: vi.fn(), findMany: vi.fn(),
  },
  scanJob: { create: vi.fn(), findFirst: vi.fn(), findMany: vi.fn(), update: vi.fn() },
  $transaction: vi.fn(),
}))
const snapshotMock = vi.hoisted(() => ({
  captureGraphSnapshot: vi.fn(),
  storeSnapshot: vi.fn(),
  ensureCurrentVersion: vi.fn(),
}))
const auditMock = vi.hoisted(() => ({ writeAudit: vi.fn() }))

vi.mock('@/lib/prisma', () => ({ default: prismaMock }))
vi.mock('@/lib/audit', () => auditMock)
vi.mock('@/lib/scanSnapshot', async orig => ({
  ...(await orig<typeof import('@/lib/scanSnapshot')>()),
  captureGraphSnapshot: (...a: unknown[]) => snapshotMock.captureGraphSnapshot(...a),
  storeSnapshot: (...a: unknown[]) => snapshotMock.storeSnapshot(...a),
  ensureCurrentVersion: (...a: unknown[]) => snapshotMock.ensureCurrentVersion(...a),
}))

import {
  parseScanMode,
  prepareVersionsForFullScan,
  createScanJob,
  recordScanStart,
  reconcileRunScanJobs,
  reconcileScanJobStatus,
  nextVersionSeq,
  rotateToNextVersion,
  rollbackPreparedVersions,
  SnapshotFreezeError,
} from './scanTimeline'
import { CurrentVersionMovedError } from './projectGraphLock'

const CURRENT = {
  id: 'vCur', seq: 2, label: 'Scan 2 - 2026-07-01 10:00 UTC',
  isCurrent: true, pinned: false, nodeCount: 100, linkCount: 200, createdAt: new Date(),
}

beforeEach(() => {
  vi.clearAllMocks()
  snapshotMock.ensureCurrentVersion.mockResolvedValue(CURRENT)
  prismaMock.scanVersion.findFirst.mockResolvedValue({ seq: 2 })
  prismaMock.scanVersion.update.mockImplementation(async ({ where, data }: never) =>
    ({ ...CURRENT, ...(data as object), id: (where as { id: string }).id }))
  prismaMock.scanVersion.updateMany.mockResolvedValue({ count: 1 })
  prismaMock.scanVersion.create.mockResolvedValue({ ...CURRENT, id: 'vNew', seq: 3, label: 'Scan 3' })
  // Run the transaction body against the same mock client.
  prismaMock.$transaction.mockImplementation(async (fn: (tx: unknown) => unknown) => fn(prismaMock))
})

describe('parseScanMode', () => {
  test('accepts only the two known modes', () => {
    expect(parseScanMode('new')).toBe('new')
    expect(parseScanMode('overwrite')).toBe('overwrite')
    for (const bad of ['NEW', 'delete', '', null, undefined, 1, {}]) {
      expect(parseScanMode(bad)).toBeNull()
    }
  })
})

describe("prepareVersionsForFullScan — mode 'new'", () => {
  test('freezes the current version, demotes it, and mints the next one', async () => {
    snapshotMock.captureGraphSnapshot.mockResolvedValue({
      nodes: [{}], relationships: [], nodeCount: 100, linkCount: 200, summary: { IP: 100 },
    })
    snapshotMock.storeSnapshot.mockResolvedValue({ bytes: 1234 })

    const res = await prepareVersionsForFullScan('p1', 'new', 'u1')

    expect(snapshotMock.captureGraphSnapshot).toHaveBeenCalledWith('p1')
    expect(snapshotMock.storeSnapshot).toHaveBeenCalledWith('vCur', expect.objectContaining({ nodeCount: 100 }))
    // Demote then create, inside one transaction.
    expect(prismaMock.$transaction).toHaveBeenCalled()
    expect(prismaMock.scanVersion.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: 'vCur', isCurrent: true }, data: { isCurrent: false } })
    )
    const created = prismaMock.scanVersion.create.mock.calls[0][0].data
    expect(created).toMatchObject({ projectId: 'p1', seq: 3, isCurrent: true, snapshot: null })
    expect(res.frozenVersionId).toBe('vCur')
    expect(res.frozenNodeCount).toBe(100)
    expect(res.currentVersion.id).toBe('vNew')
  })

  test('FAIL CLOSED: capture failure throws and nothing is demoted or created', async () => {
    snapshotMock.captureGraphSnapshot.mockRejectedValue(new Error('neo4j unreachable'))
    await expect(prepareVersionsForFullScan('p1', 'new', 'u1'))
      .rejects.toBeInstanceOf(SnapshotFreezeError)
    expect(snapshotMock.storeSnapshot).not.toHaveBeenCalled()
    expect(prismaMock.scanVersion.updateMany).not.toHaveBeenCalled()
    expect(prismaMock.scanVersion.create).not.toHaveBeenCalled()
  })

  test('FAIL CLOSED: store failure throws and nothing is demoted or created', async () => {
    snapshotMock.captureGraphSnapshot.mockResolvedValue({
      nodes: [{}], relationships: [], nodeCount: 5, linkCount: 1, summary: {},
    })
    snapshotMock.storeSnapshot.mockRejectedValue(new Error('snapshot too large'))
    await expect(prepareVersionsForFullScan('p1', 'new', 'u1'))
      .rejects.toThrow(/Could not store the snapshot/)
    expect(prismaMock.scanVersion.updateMany).not.toHaveBeenCalled()
    expect(prismaMock.scanVersion.create).not.toHaveBeenCalled()
  })

  test('an empty live graph is not frozen and does not consume a version', async () => {
    snapshotMock.captureGraphSnapshot.mockResolvedValue({
      nodes: [], relationships: [], nodeCount: 0, linkCount: 0, summary: {},
    })
    const res = await prepareVersionsForFullScan('p1', 'new', 'u1')
    expect(snapshotMock.storeSnapshot).not.toHaveBeenCalled()
    expect(prismaMock.scanVersion.create).not.toHaveBeenCalled()
    expect(res.frozenVersionId).toBeNull()
    expect(res.currentVersion.id).toBe('vCur')
  })
})

describe("prepareVersionsForFullScan — mode 'overwrite'", () => {
  test('keeps the current version, takes NO snapshot, and audits the discard', async () => {
    const res = await prepareVersionsForFullScan('p1', 'overwrite', 'u1')
    expect(snapshotMock.captureGraphSnapshot).not.toHaveBeenCalled()
    expect(snapshotMock.storeSnapshot).not.toHaveBeenCalled()
    expect(prismaMock.scanVersion.create).not.toHaveBeenCalled()
    expect(res.frozenVersionId).toBeNull()
    expect(res.currentVersion.id).toBe('vCur')
    expect(auditMock.writeAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'scan-version.overwrite', actorId: 'u1', targetId: 'vCur',
    }))
  })

  test('refreshes an auto-generated label but preserves a user rename', async () => {
    await prepareVersionsForFullScan('p1', 'overwrite', 'u1')
    const autoLabel = prismaMock.scanVersion.update.mock.calls[0][0].data.label
    expect(autoLabel).toMatch(/^Scan 2 - \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/)
    expect(autoLabel).not.toBe(CURRENT.label)

    vi.clearAllMocks()
    snapshotMock.ensureCurrentVersion.mockResolvedValue({ ...CURRENT, label: 'Pre-migration baseline' })
    prismaMock.scanVersion.update.mockResolvedValue(CURRENT)
    await prepareVersionsForFullScan('p1', 'overwrite', 'u1')
    expect(prismaMock.scanVersion.update.mock.calls[0][0].data.label).toBe('Pre-migration baseline')
  })
})

describe('rotateToNextVersion — concurrent writers (double-submit)', () => {
  test('a seq collision is retried with a recomputed seq instead of failing the request', async () => {
    // Two starts (or a double-clicked button) can both read max(seq)=2 and both
    // try to create seq=3. @@unique([projectId, seq]) rejects the loser, which
    // used to surface as a 500 AFTER its snapshot had already been frozen.
    let attempt = 0
    prismaMock.scanVersion.findFirst
      .mockResolvedValueOnce({ seq: 2 })   // first attempt computes 3
      .mockResolvedValueOnce({ seq: 3 })   // the winner took 3, so retry computes 4
    prismaMock.scanVersion.create.mockImplementation(async ({ data }: never) => {
      attempt += 1
      if (attempt === 1) throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' })
      return { ...CURRENT, id: 'vNew', seq: (data as { seq: number }).seq }
    })

    const created = await rotateToNextVersion('p1', 'vCur')
    expect(attempt).toBe(2)
    expect(created.seq).toBe(4)
  })

  test('a non-collision error is not retried', async () => {
    prismaMock.scanVersion.findFirst.mockResolvedValue({ seq: 2 })
    prismaMock.scanVersion.create.mockRejectedValue(new Error('disk on fire'))
    await expect(rotateToNextVersion('p1', 'vCur')).rejects.toThrow('disk on fire')
    expect(prismaMock.scanVersion.create).toHaveBeenCalledTimes(1)
  })

  test('it gives up after a bounded number of retries', async () => {
    prismaMock.scanVersion.findFirst.mockResolvedValue({ seq: 2 })
    prismaMock.scanVersion.create.mockRejectedValue(
      Object.assign(new Error('Unique constraint failed'), { code: 'P2002' })
    )
    await expect(rotateToNextVersion('p1', 'vCur')).rejects.toMatchObject({ code: 'P2002' })
    expect(prismaMock.scanVersion.create.mock.calls.length).toBeLessThanOrEqual(4)
  })

  test('the demote and the create happen in ONE transaction (never a project with no current)', async () => {
    prismaMock.scanVersion.findFirst.mockResolvedValue({ seq: 2 })
    prismaMock.scanVersion.create.mockResolvedValue({ ...CURRENT, id: 'vNew', seq: 3 })
    await rotateToNextVersion('p1', 'vCur')
    expect(prismaMock.$transaction).toHaveBeenCalled()
    expect(prismaMock.scanVersion.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: 'vCur', isCurrent: true }, data: { isCurrent: false } })
    )
  })

  test('a version another writer already demoted is refused, never a second current version (S-4)', async () => {
    // A writer outside the project graph lock read vCur as current, then lost
    // the race: the winner demoted vCur and opened its own current version.
    prismaMock.scanVersion.updateMany.mockResolvedValue({ count: 0 })
    await expect(rotateToNextVersion('p1', 'vCur')).rejects.toBeInstanceOf(CurrentVersionMovedError)
    expect(prismaMock.scanVersion.create).not.toHaveBeenCalled()
  })
})

describe('nextVersionSeq', () => {
  test('is max(seq) + 1, and 1 for a project with no versions', async () => {
    prismaMock.scanVersion.findFirst.mockResolvedValue({ seq: 7 })
    expect(await nextVersionSeq('p1')).toBe(8)
    prismaMock.scanVersion.findFirst.mockResolvedValue(null)
    expect(await nextVersionSeq('p1')).toBe(1)
  })
})

describe('createScanJob', () => {
  test('a running job records startedAt; a non-running one does not', async () => {
    prismaMock.scanJob.create.mockResolvedValue({ id: 'j1' })
    await createScanJob({ projectId: 'p1', versionId: 'v1', trigger: 'manual', mode: 'new', initiatedByUserId: 'u1' })
    let data = prismaMock.scanJob.create.mock.calls[0][0].data
    expect(data).toMatchObject({ projectId: 'p1', versionId: 'v1', trigger: 'manual', mode: 'new', status: 'running', initiatedByUserId: 'u1' })
    expect(data.startedAt).toBeInstanceOf(Date)

    prismaMock.scanJob.create.mockClear()
    await createScanJob({ projectId: 'p1', trigger: 'scheduled', mode: 'new', status: 'deferred_ram', ramReason: 'graph busy' })
    data = prismaMock.scanJob.create.mock.calls[0][0].data
    expect(data.status).toBe('deferred_ram')
    expect(data.ramReason).toBe('graph busy')
    expect(data.startedAt).toBeNull()
  })
})

describe('recordScanStart', () => {
  // Every kind writes a ScanJob now. Before this, a directly-started GVM or
  // supply-chain scan left no row at all and vanished from history when it ended.
  test('records the kind and marks the row running', async () => {
    prismaMock.scanJob.create.mockResolvedValue({ id: 'j9' })
    await recordScanStart({ projectId: 'p1', kind: 'supply_chain', initiatedByUserId: 'u1' })
    const data = prismaMock.scanJob.create.mock.calls[0][0].data
    expect(data).toMatchObject({
      projectId: 'p1', kind: 'supply_chain', status: 'running',
      trigger: 'manual', mode: null, versionId: null, initiatedByUserId: 'u1',
    })
  })

  test('a run-keyed kind carries its run id', async () => {
    prismaMock.scanJob.create.mockResolvedValue({ id: 'j9' })
    await recordScanStart({ projectId: 'p1', kind: 'partial_recon', runId: 'r1' })
    expect(prismaMock.scanJob.create.mock.calls[0][0].data).toMatchObject({ kind: 'partial_recon', runId: 'r1' })
  })

  test('a scheduled origin is recorded as such', async () => {
    prismaMock.scanJob.create.mockResolvedValue({ id: 'j9' })
    await recordScanStart({ projectId: 'p1', kind: 'gvm', scheduleId: 's1' })
    expect(prismaMock.scanJob.create.mock.calls[0][0].data).toMatchObject({ trigger: 'scheduled', scheduleId: 's1' })
  })

  // The audit record of scope: which roots a multi-root partial run covered.
  test('the roots a run covers are stored as its targets', async () => {
    prismaMock.scanJob.create.mockResolvedValue({ id: 'j9' })
    await recordScanStart({
      projectId: 'p1', kind: 'partial_recon', runId: 'r1',
      targets: ['alpha.test', 'beta.test', 'gamma.test'],
    })
    expect(prismaMock.scanJob.create.mock.calls[0][0].data.targets)
      .toEqual(['alpha.test', 'beta.test', 'gamma.test'])
  })

  test('a kind that reports no roots stores an empty list', async () => {
    prismaMock.scanJob.create.mockResolvedValue({ id: 'j9' })
    await recordScanStart({ projectId: 'p1', kind: 'gvm' })
    expect(prismaMock.scanJob.create.mock.calls[0][0].data.targets).toEqual([])
  })

  // History is a side effect of starting a scan; it must never fail the start.
  test('a DB failure never propagates to the caller', async () => {
    prismaMock.scanJob.create.mockRejectedValue(new Error('db down'))
    await expect(recordScanStart({ projectId: 'p1', kind: 'gvm' })).resolves.toBeNull()
  })

  // The queue links its row to this id, or the jobs list shows the scan twice.
  test('returns the id of the row it wrote', async () => {
    prismaMock.scanJob.create.mockResolvedValue({ id: 'j9' })
    await expect(recordScanStart({ projectId: 'p1', kind: 'gvm' })).resolves.toBe('j9')
  })

  test('an unattended start with no schedule can say so', async () => {
    prismaMock.scanJob.create.mockResolvedValue({ id: 'j9' })
    await recordScanStart({ projectId: 'p1', kind: 'gvm', trigger: 'scheduled' })
    expect(prismaMock.scanJob.create.mock.calls[0][0].data).toMatchObject({ trigger: 'scheduled', scheduleId: null })
  })
})

describe('reconcileRunScanJobs', () => {
  beforeEach(() => {
    prismaMock.scanJob.update.mockResolvedValue({})
  })

  test('closes each open run from its own live status', async () => {
    prismaMock.scanJob.findMany.mockResolvedValue([
      { id: 'j1', runId: 'r1' }, { id: 'j2', runId: 'r2' }, { id: 'j3', runId: 'r3' },
    ])
    await reconcileRunScanJobs('p1', 'partial_recon', [
      { run_id: 'r1', status: 'completed' },
      { run_id: 'r2', status: 'error' },
      { run_id: 'r3', status: 'running' },
    ])
    const byId = Object.fromEntries(
      prismaMock.scanJob.update.mock.calls.map(c => [c[0].where.id, c[0].data.status]))
    expect(byId).toEqual({ j1: 'completed', j2: 'failed' })
  })

  // A run vanishes from the list when the orchestrator restarts too; calling that
  // 'completed' would invent an outcome the scan never reported.
  test('a run missing from the list is left running, not invented as completed', async () => {
    prismaMock.scanJob.findMany.mockResolvedValue([{ id: 'j1', runId: 'gone' }])
    await reconcileRunScanJobs('p1', 'partial_recon', [{ run_id: 'other', status: 'completed' }])
    expect(prismaMock.scanJob.update).not.toHaveBeenCalled()
  })

  test('no open rows → no per-run work', async () => {
    prismaMock.scanJob.findMany.mockResolvedValue([])
    await reconcileRunScanJobs('p1', 'ai_attack', [{ run_id: 'r1', status: 'completed' }])
    expect(prismaMock.scanJob.update).not.toHaveBeenCalled()
  })

  test('an empty or non-array payload does no DB work at all', async () => {
    await reconcileRunScanJobs('p1', 'ai_attack', [])
    await reconcileRunScanJobs('p1', 'ai_attack', undefined)
    await reconcileRunScanJobs('p1', 'ai_attack', { runs: 'nope' })
    expect(prismaMock.scanJob.findMany).not.toHaveBeenCalled()
  })

  test('swallows DB errors so a list poll never breaks', async () => {
    prismaMock.scanJob.findMany.mockRejectedValue(new Error('db down'))
    await expect(reconcileRunScanJobs('p1', 'gvm', [{ run_id: 'r', status: 'completed' }]))
      .resolves.toBeUndefined()
  })
})

describe('reconcileScanJobStatus', () => {
  beforeEach(() => {
    prismaMock.scanJob.findFirst.mockResolvedValue({ id: 'j1', versionId: 'v1' })
    prismaMock.scanVersion.findUnique.mockResolvedValue({ nodeCount: 42 })
    prismaMock.scanJob.update.mockResolvedValue({})
  })

  test('maps terminal orchestrator states onto the open job', async () => {
    for (const [status, expected] of [['completed', 'completed'], ['error', 'failed'], ['idle', 'canceled']]) {
      prismaMock.scanJob.update.mockClear()
      await reconcileScanJobStatus('p1', status)
      expect(prismaMock.scanJob.update.mock.calls[0][0].data).toMatchObject({ status: expected, nodeCount: 42 })
    }
  })

  test('leaves non-terminal states alone (no DB work at all)', async () => {
    for (const status of ['running', 'starting', 'paused', 'stopping', undefined, null]) {
      await reconcileScanJobStatus('p1', status)
    }
    expect(prismaMock.scanJob.findFirst).not.toHaveBeenCalled()
    expect(prismaMock.scanJob.update).not.toHaveBeenCalled()
  })

  // A GVM poll closing "the project's open job" would have ended the full recon's
  // history row instead of GVM's.
  test('only ever closes the open job of the polled kind', async () => {
    await reconcileScanJobStatus('p1', 'completed', { kind: 'gvm' })
    expect(prismaMock.scanJob.findFirst.mock.calls[0][0].where).toMatchObject({
      projectId: 'p1', kind: 'gvm', status: { in: ['running'] },
    })
  })

  test('defaults to full_recon, the only kind that used to exist', async () => {
    await reconcileScanJobStatus('p1', 'completed')
    expect(prismaMock.scanJob.findFirst.mock.calls[0][0].where).toMatchObject({ kind: 'full_recon' })
  })

  test('a run-keyed kind narrows to the run', async () => {
    await reconcileScanJobStatus('p1', 'completed', { kind: 'partial_recon', runId: 'r7' })
    expect(prismaMock.scanJob.findFirst.mock.calls[0][0].where).toMatchObject({ runId: 'r7' })
  })

  test('no open job → no update', async () => {
    prismaMock.scanJob.findFirst.mockResolvedValue(null)
    await reconcileScanJobStatus('p1', 'completed')
    expect(prismaMock.scanJob.update).not.toHaveBeenCalled()
  })

  test('swallows DB errors so a status poll never breaks', async () => {
    prismaMock.scanJob.findFirst.mockRejectedValue(new Error('db down'))
    await expect(reconcileScanJobStatus('p1', 'completed')).resolves.toBeUndefined()
  })
})

// P0-2. prepareVersionsForFullScan used to run retention itself, so a start the
// orchestrator went on to refuse still evicted the oldest saved version. It is
// now the caller's job, after acceptance, and a refusal is undone here.
describe('P0-2: rollbackPreparedVersions', () => {
  const prepared = (frozenVersionId: string | null) => ({
    currentVersion: { ...CURRENT, id: 'vNew', seq: 3 },
    frozenVersionId,
    frozenNodeCount: frozenVersionId ? 120 : 0,
  })

  test('deletes the minted version and makes the frozen one current again', async () => {
    const ok = await rollbackPreparedVersions('p1', prepared('vCur'))

    expect(ok).toBe(true)
    expect(prismaMock.scanVersion.delete).toHaveBeenCalledWith({ where: { id: 'vNew' } })
    expect(prismaMock.scanVersion.update).toHaveBeenCalledWith({
      where: { id: 'vCur' },
      data: { isCurrent: true, snapshot: null },
    })
  })

  test('clears the stored snapshot bytes so a retry loop cannot accrete copies', async () => {
    await rollbackPreparedVersions('p1', prepared('vCur'))
    const call = prismaMock.scanVersion.update.mock.calls.at(-1)![0] as { data: { snapshot: unknown } }
    expect(call.data.snapshot).toBeNull()
  })

  test('runs as ONE transaction, so it cannot leave two current versions', async () => {
    await rollbackPreparedVersions('p1', prepared('vCur'))
    expect(prismaMock.$transaction).toHaveBeenCalledOnce()
  })

  test('is a no-op when nothing was rotated (overwrite, or an empty graph)', async () => {
    const ok = await rollbackPreparedVersions('p1', prepared(null))

    expect(ok).toBe(false)
    expect(prismaMock.$transaction).not.toHaveBeenCalled()
    expect(prismaMock.scanVersion.delete).not.toHaveBeenCalled()
  })

  test('never throws: a start has already failed and must keep its own error', async () => {
    prismaMock.$transaction.mockRejectedValue(new Error('db down'))
    await expect(rollbackPreparedVersions('p1', prepared('vCur'))).resolves.toBe(false)
  })
})

describe('P0-2: prepare no longer runs retention', () => {
  test("a 'new' preparation does not touch past versions", async () => {
    snapshotMock.captureGraphSnapshot.mockResolvedValue({ nodeCount: 5, linkCount: 3, summary: {} })
    snapshotMock.storeSnapshot.mockResolvedValue({ bytes: 10 })
    // Retention's first act is to list deletion candidates, so an unused
    // findMany is the proof that prepare no longer runs it.
    prismaMock.scanVersion.findMany.mockResolvedValue([])

    await prepareVersionsForFullScan('p1', 'new', 'u1')

    expect(prismaMock.scanVersion.findMany).not.toHaveBeenCalled()
  })
})
