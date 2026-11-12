/**
 * Scan Timeline — POST .../versions/[versionId]/activate (Section 4A).
 *
 * The gate for this step. What must hold, in order:
 *   - authorization + version ownership (BOLA), before any graph work
 *   - a version with no restorable bytes is refused (4A.6)
 *   - activation is refused while a scan / partial / agent holds the graph (4A.3)
 *   - FREEZE BEFORE CLEAR: if the freeze fails, nothing is deleted (Risk 7)
 *   - the pointer moves ONLY after the restore succeeds; a mid-restore failure is
 *     reported as retriable with no data lost
 *   - agent session nodes are excluded from the clear (F1)
 *   - the lock is always released, and the graph cache invalidated
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  requireEff: vi.fn(),
  requireProjectAccess: vi.fn(),
  requireVersion: vi.fn(),
  describeWriters: vi.fn(),
  acquire: vi.fn(),
  release: vi.fn(),
  capture: vi.fn(),
  store: vi.fn(),
  load: vi.fn(),
  ensureCurrent: vi.fn(),
  clearGraph: vi.fn(),
  restore: vi.fn(),
  invalidate: vi.fn(),
  txUpdate: vi.fn(),
  txUpdateMany: vi.fn(),
  transaction: vi.fn(),
  closeSession: vi.fn(),
  nodeFilterWriter: vi.fn(),
  sweep: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.requireEff(),
  requireProjectAccess: (...a: unknown[]) => h.requireProjectAccess(...a),
}))
vi.mock('@/lib/scanVersionAccess', () => ({
  requireVersionInProject: (...a: unknown[]) => h.requireVersion(...a),
}))
vi.mock('@/lib/graphWriters', () => ({
  describeLiveGraphWriters: (...a: unknown[]) => h.describeWriters(...a),
}))
vi.mock('@/lib/nodeFilterRun', () => ({
  describeNodeFilterWriter: (...a: unknown[]) => h.nodeFilterWriter(...a),
}))
vi.mock('@/lib/activationLock', () => ({
  acquireActivationLock: (...a: unknown[]) => h.acquire(...a),
  releaseActivationLock: (...a: unknown[]) => h.release(...a),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/prisma', () => ({
  default: {
    $transaction: (...a: unknown[]) => h.transaction(...a),
    scanVersion: { update: h.txUpdate, updateMany: h.txUpdateMany },
  },
}))
vi.mock('@/lib/scanSnapshot', async orig => ({
  ...(await orig<typeof import('@/lib/scanSnapshot')>()),
  captureGraphSnapshot: (...a: unknown[]) => h.capture(...a),
  storeSnapshot: (...a: unknown[]) => h.store(...a),
  loadSnapshot: (...a: unknown[]) => h.load(...a),
  ensureCurrentVersion: (...a: unknown[]) => h.ensureCurrent(...a),
}))
vi.mock('@/lib/graphRestore', () => ({
  clearProjectGraph: (...a: unknown[]) => h.clearGraph(...a),
  restoreGraph: (...a: unknown[]) => h.restore(...a),
  sweepOrphanReferenceNodes: (...a: unknown[]) => h.sweep(...a),
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: vi.fn(), close: h.closeSession }),
}))
vi.mock('@/app/api/graph/cache', () => ({ invalidateCache: (...a: unknown[]) => h.invalidate(...a) }))

import { POST } from './route'
import { SESSION_LABELS } from '@/lib/scanSnapshot'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const params = (id: string, versionId: string) => ({ params: Promise.resolve({ id, versionId }) })
const req = () => new NextRequest('http://x/api/projects/p1/versions/v1/activate', { method: 'POST' })

const TARGET = {
  id: 'v1', projectId: 'p1', seq: 1, label: 'Scan 1', isCurrent: false,
  pinned: false, nodeCount: 3, linkCount: 2, createdAt: new Date(), hasSnapshot: true,
}

beforeEach(() => {
  vi.clearAllMocks()
  h.requireEff.mockResolvedValue({ userId: 'owner' })
  h.requireProjectAccess.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
  h.requireVersion.mockResolvedValue(TARGET)
  h.describeWriters.mockResolvedValue(null)
  h.nodeFilterWriter.mockResolvedValue(null)
  h.acquire.mockResolvedValue({ acquired: true })
  h.release.mockResolvedValue(undefined)
  h.ensureCurrent.mockResolvedValue({ id: 'v2', seq: 2, label: 'Scan 2' })
  h.capture.mockResolvedValue({ nodes: [{}], relationships: [], nodeCount: 7, linkCount: 3, summary: {} })
  h.store.mockResolvedValue({ bytes: 100 })
  h.load.mockResolvedValue({
    nodes: [{ labels: ['IP'], properties: {}, _exportId: 'n1' }],
    relationships: [],
  })
  h.restore.mockResolvedValue({ nodes: 1, relationships: 0 })
  h.clearGraph.mockResolvedValue(undefined)
  h.transaction.mockImplementation(async (fn: (tx: unknown) => unknown) =>
    fn({ scanVersion: { update: h.txUpdate, updateMany: h.txUpdateMany } }))
})

describe('authorization', () => {
  test("another user's project → 404 before any lock or graph work", async () => {
    h.requireProjectAccess.mockResolvedValue(NOT_FOUND)
    const res = await POST(req(), params('victimProj', 'v1'))
    expect(res.status).toBe(404)
    expect(h.requireVersion).not.toHaveBeenCalled()
    expect(h.acquire).not.toHaveBeenCalled()
    expect(h.clearGraph).not.toHaveBeenCalled()
  })

  test("EXPLOIT: a version id from another project → 404, graph untouched", async () => {
    h.requireVersion.mockResolvedValue(NOT_FOUND)
    const res = await POST(req(), params('p1', 'vSomeoneElse'))
    expect(res.status).toBe(404)
    expect(h.acquire).not.toHaveBeenCalled()
    expect(h.clearGraph).not.toHaveBeenCalled()
  })
})

describe('preconditions', () => {
  test('activating the already-current version is a no-op', async () => {
    h.requireVersion.mockResolvedValue({ ...TARGET, isCurrent: true })
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(200)
    expect((await res.json()).alreadyCurrent).toBe(true)
    expect(h.acquire).not.toHaveBeenCalled()
    expect(h.clearGraph).not.toHaveBeenCalled()
  })

  test('NEVER freezes the live graph onto the version it is about to restore', async () => {
    // If no row is marked current (e.g. a crashed activation, or an import whose
    // archive carried no current flag), ensureCurrentVersion adopts the highest
    // seq — which can be the very version being activated. Freezing onto it would
    // overwrite the bytes we are about to restore with the CURRENT graph, i.e.
    // silently destroy the version the user asked for.
    h.ensureCurrent.mockResolvedValue({ id: 'v1', seq: 1, label: 'Scan 1' })  // == target
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(200)
    expect((await res.json()).alreadyCurrent).toBe(true)
    expect(h.store).not.toHaveBeenCalled()
    expect(h.clearGraph).not.toHaveBeenCalled()
    expect(h.restore).not.toHaveBeenCalled()
    expect(h.release).toHaveBeenCalledWith('p1')
  })

  test('IDEMPOTENT: activating the same version twice leaves the same state', async () => {
    // First call swaps; the second sees it is already current and must not clear,
    // restore, freeze again, or move the pointer a second time.
    const first = await POST(req(), params('p1', 'v1'))
    expect(first.status).toBe(200)
    expect(h.clearGraph).toHaveBeenCalledTimes(1)

    vi.clearAllMocks()
    h.requireEff.mockResolvedValue({ userId: 'owner' })
    h.requireProjectAccess.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
    h.requireVersion.mockResolvedValue({ ...TARGET, isCurrent: true })   // now current

    const second = await POST(req(), params('p1', 'v1'))
    expect(second.status).toBe(200)
    expect((await second.json()).alreadyCurrent).toBe(true)
    expect(h.clearGraph).not.toHaveBeenCalled()
    expect(h.restore).not.toHaveBeenCalled()
    expect(h.store).not.toHaveBeenCalled()
    expect(h.txUpdate).not.toHaveBeenCalled()
  })

  test('a version with no stored bytes is refused (4A.6)', async () => {
    h.requireVersion.mockResolvedValue({ ...TARGET, hasSnapshot: false })
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(409)
    expect((await res.json()).notActivatable).toBe(true)
    expect(h.clearGraph).not.toHaveBeenCalled()
  })

  test.each([
    'a full recon scan is running',
    'a partial recon run is active',
    'an agent session is running',
    // Secondary graph writers must block activation too (alignment fix).
    'a GVM vulnerability scan is running',
    'a GitHub Secret Hunt is running',
    'a Secret Multiscanner scan is running',
  ])('refused while %s (4A.3)', async reason => {
    h.describeWriters.mockResolvedValue(reason)
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(409)
    expect((await res.json()).busy).toBe(reason)
    expect(h.acquire).not.toHaveBeenCalled()
    expect(h.clearGraph).not.toHaveBeenCalled()
  })

  test('a concurrent activation cannot take the lock', async () => {
    h.acquire.mockResolvedValue({ acquired: false, reason: 'Another activation is already in progress for this project.' })
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(409)
    expect(h.clearGraph).not.toHaveBeenCalled()
    // Nothing was taken, so nothing must be released either.
    expect(h.release).not.toHaveBeenCalled()
  })

  test('a failing node-filter check under the lock releases the lock and answers its code', async () => {
    h.nodeFilterWriter.mockRejectedValue(Object.assign(new Error('pool exhausted'), { code: 'P2024' }))
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Activation failed', code: 'P2024' })
    expect(h.release).toHaveBeenCalledWith('p1')
    expect(h.clearGraph).not.toHaveBeenCalled()
  })
})

describe('the swap', () => {
  test('freezes the OUTGOING current from LIVE, then clears, restores, then moves the pointer', async () => {
    const order: string[] = []
    h.capture.mockImplementation(async () => { order.push('freeze'); return { nodes: [{}], relationships: [], nodeCount: 7, linkCount: 3, summary: {} } })
    h.store.mockImplementation(async () => { order.push('store'); return { bytes: 1 } })
    h.clearGraph.mockImplementation(async () => { order.push('clear') })
    h.restore.mockImplementation(async () => { order.push('restore'); return { nodes: 1, relationships: 0 } })
    h.transaction.mockImplementation(async (fn: (tx: unknown) => unknown) => {
      order.push('pointer')
      return fn({ scanVersion: { update: h.txUpdate, updateMany: h.txUpdateMany } })
    })

    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(200)
    expect(order).toEqual(['freeze', 'store', 'clear', 'restore', 'pointer'])
    // Risk 10: the freeze reads the LIVE graph, not the outgoing version's bytes.
    expect(h.capture).toHaveBeenCalledWith('p1')
    expect(h.store).toHaveBeenCalledWith('v2', expect.objectContaining({ nodeCount: 7 }))
  })

  test('the clear preserves agent session nodes (F1)', async () => {
    await POST(req(), params('p1', 'v1'))
    expect(h.clearGraph).toHaveBeenCalledWith(expect.anything(), 'p1', SESSION_LABELS, { sweep: false })
  })

  test('the version links back to the CVE catalogue, and the orphan sweep waits for the restore (plan 09.5)', async () => {
    // Swept between the clear and the restore, a CVE only this project linked
    // would be gone before the restore could link it back.
    const links = [{ startExportId: 'n1', endExportId: null, type: 'HAS_KNOWN_CVE',
      refLabel: 'CVE', refKey: 'CVE-2021-23017', properties: {} }]
    h.load.mockResolvedValue({ nodes: [{ labels: ['IP'], properties: {}, _exportId: 'n1' }],
      relationships: [], referenceLinks: links })
    const order: string[] = []
    h.clearGraph.mockImplementation(async () => { order.push('clear') })
    h.restore.mockImplementation(async () => { order.push('restore'); return { nodes: 1, relationships: 0 } })
    h.sweep.mockImplementation(async () => { order.push('sweep') })

    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(200)
    expect(order).toEqual(['clear', 'restore', 'sweep'])
    expect(h.restore.mock.calls[0][3]).toEqual({ projectId: 'p1', referenceLinks: links })
  })

  test('the restore keeps the project id (no re-owning) and the cache is invalidated', async () => {
    await POST(req(), params('p1', 'v1'))
    const opts = h.restore.mock.calls[0][3]
    expect(opts).toEqual({ projectId: 'p1' })
    expect(h.invalidate).toHaveBeenCalledWith('p1')
  })

  test('the pointer move demotes every other current and promotes the target', async () => {
    await POST(req(), params('p1', 'v1'))
    expect(h.txUpdateMany).toHaveBeenCalledWith({
      where: { projectId: 'p1', isCurrent: true }, data: { isCurrent: false },
    })
    // The promoted version becomes the live graph, so it must SHED its snapshot
    // bytes (the invariant is "the current version has snapshot=null"). Keeping
    // them leaves a full duplicate of the graph in Postgres and a stale copy that
    // future readers could trust. Regression: activation used to set only
    // isCurrent:true, leaving the activated version current WITH bytes.
    expect(h.txUpdate).toHaveBeenCalledWith({
      where: { id: 'v1' }, data: { isCurrent: true, snapshot: null },
    })
  })

  test('an empty outgoing graph is not stored as an empty snapshot', async () => {
    h.capture.mockResolvedValue({ nodes: [], relationships: [], nodeCount: 0, linkCount: 0, summary: {} })
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(200)
    expect(h.store).not.toHaveBeenCalled()
    expect((await res.json()).frozenVersionId).toBeNull()
  })
})

describe('failure modes', () => {
  test('FAIL CLOSED: a freeze failure aborts BEFORE any delete', async () => {
    h.capture.mockRejectedValue(new Error('neo4j unreachable'))
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(500)
    expect((await res.json()).freezeFailed).toBe(true)
    expect(h.clearGraph).not.toHaveBeenCalled()
    expect(h.restore).not.toHaveBeenCalled()
    expect(h.txUpdate).not.toHaveBeenCalled()
    expect(h.release).toHaveBeenCalledWith('p1')
  })

  test('FAIL CLOSED: a store failure also aborts before any delete', async () => {
    h.store.mockRejectedValue(new Error('snapshot too large'))
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(500)
    expect(h.clearGraph).not.toHaveBeenCalled()
  })

  test('a mid-restore failure is retriable and does NOT move the pointer (Risk 7)', async () => {
    h.restore.mockRejectedValue(new Error('apoc exploded'))
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body.restoreFailed).toBe(true)
    expect(body.retriable).toBe(true)
    expect(h.txUpdate).not.toHaveBeenCalled()
    expect(h.txUpdateMany).not.toHaveBeenCalled()
    // Both endpoints are safe in Postgres: the outgoing version was frozen first.
    expect(h.store).toHaveBeenCalled()
    // The transiently-inconsistent live graph must not be served from cache.
    expect(h.invalidate).toHaveBeenCalledWith('p1')
    expect(h.release).toHaveBeenCalledWith('p1')
  })

  test('the lock is released even when the handler throws unexpectedly', async () => {
    h.ensureCurrent.mockRejectedValue(new Error('boom'))
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(500)
    expect(h.release).toHaveBeenCalledWith('p1')
  })

  test('a freeze failure answers the fixed reason and the Neo4j code, never the exception text', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.capture.mockRejectedValue(Object.assign(new Error('MATCH (n {project_id: "p1"}) failed on host 10.0.0.7'), {
      code: 'Neo.TransientError.General.DatabaseUnavailable',
    }))
    const res = await POST(req(), params('p1', 'v1'))
    expect(await res.json()).toEqual({
      error: 'Could not save the current graph before switching, so nothing was changed.',
      code: 'Neo.TransientError.General.DatabaseUnavailable',
      freezeFailed: true,
    })
  })

  test('a mid-restore failure keeps its flags and drops the exception text', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.restore.mockRejectedValue(new Error('apoc exploded on node alpha.test'))
    const body = await (await POST(req(), params('p1', 'v1'))).json()
    expect(body).toEqual({
      error: 'Activation failed while rebuilding the graph. No version data was lost - retry the activation to rebuild it.',
      code: 'internal_error', restoreFailed: true, retriable: true,
    })
  })

  test('a throw before the lock answers a readable 500, not an empty body', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.describeWriters.mockRejectedValue(Object.assign(new Error('pool exhausted'), { code: 'P2024' }))
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Activation failed', code: 'P2024' })
  })

  test('the Neo4j session is closed even when the restore throws', async () => {
    h.restore.mockRejectedValue(new Error('apoc exploded'))
    await POST(req(), params('p1', 'v1'))
    expect(h.closeSession).toHaveBeenCalled()
  })
})

describe('a node-filter apply that started between the writer check and the lock', () => {
  test('is caught under the lock: nothing is frozen, and the lock is released', async () => {
    // describeLiveGraphWriters saw an idle graph, then an apply started before
    // the lock was taken. The freeze would capture a half-applied graph.
    h.nodeFilterWriter.mockResolvedValue('mute rules are being applied to the graph')
    const res = await POST(req(), params('p1', 'v1'))
    expect(res.status).toBe(409)
    expect((await res.json()).error).toMatch(/mute rules are being applied/)
    expect(h.capture).not.toHaveBeenCalled()
    expect(h.clearGraph).not.toHaveBeenCalled()
    expect(h.release).toHaveBeenCalledWith('p1')
  })
})
