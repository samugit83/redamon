/**
 * BOLA — GET/POST /api/projects/[id]/versions.
 *
 * The list leaks a project's scan history; the POST freezes that project's live
 * graph into stored bytes. Both must prove project ownership BEFORE any DB or
 * Neo4j work, and POST must additionally refuse while the graph is being swapped.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockRequireEff = vi.fn()
const mockRequireProjectAccess = vi.fn()
const mockQueryRaw = vi.fn()
const mockEnsureCurrent = vi.fn()
const mockCapture = vi.fn()
const mockStore = vi.fn()
const mockIsActivating = vi.fn()
const mockBusy = vi.fn()
const mockUpdate = vi.fn()
const mockCreate = vi.fn()
const mockTransaction = vi.fn()
const mockRotate = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => mockRequireEff(),
  requireProjectAccess: (...a: unknown[]) => mockRequireProjectAccess(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    $queryRaw: (...a: unknown[]) => mockQueryRaw(...a),
    $transaction: (...a: unknown[]) => mockTransaction(...a),
    scanVersion: {
      update: (...a: unknown[]) => mockUpdate(...a),
      create: (...a: unknown[]) => mockCreate(...a),
      findFirst: vi.fn().mockResolvedValue({ seq: 2 }),
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/activationLock', () => ({
  isActivationInProgress: (...a: unknown[]) => mockIsActivating(...a),
}))
vi.mock('@/lib/graphWriters', () => ({
  describeScanWriters: (...a: unknown[]) => mockBusy(...a),
  // The save path now blocks on the secondary writers too: TruffleHog and the
  // other finding scanners stream into the LIVE graph, so a snapshot taken
  // mid-write captures a partial subgraph.
  describeSecondaryScanWriters: async () => null,
}))
vi.mock('@/lib/scanSnapshot', async orig => ({
  ...(await orig<typeof import('@/lib/scanSnapshot')>()),
  captureGraphSnapshot: (...a: unknown[]) => mockCapture(...a),
  storeSnapshot: (...a: unknown[]) => mockStore(...a),
  ensureCurrentVersion: (...a: unknown[]) => mockEnsureCurrent(...a),
}))
vi.mock('@/lib/scanTimeline', () => ({
  rotateToNextVersion: (...a: unknown[]) => mockRotate(...a),
}))

import { GET, POST } from './route'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const UNAUTH = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const get = () => new NextRequest('http://x/api/projects/p1/versions')
const post = (body: unknown = {}) => new NextRequest('http://x/api/projects/p1/versions', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
})

beforeEach(() => {
  vi.clearAllMocks()
  mockRequireEff.mockResolvedValue({ userId: 'owner' })
  mockRequireProjectAccess.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
  mockQueryRaw.mockResolvedValue([])
  mockEnsureCurrent.mockResolvedValue({ id: 'vCur', seq: 2, label: 'Scan 2' })
  mockIsActivating.mockResolvedValue(false)
  mockBusy.mockResolvedValue(null)
  mockCapture.mockResolvedValue({ nodes: [{}], relationships: [], nodeCount: 5, linkCount: 2, summary: {} })
  mockStore.mockResolvedValue({ bytes: 100 })
  mockTransaction.mockImplementation(async (fn: (tx: unknown) => unknown) =>
    fn({ scanVersion: { update: mockUpdate, create: mockCreate } }))
  mockCreate.mockResolvedValue({ id: 'vNew', seq: 3, label: 'Scan 3' })
  mockRotate.mockResolvedValue({ id: 'vNew', seq: 3, label: 'Scan 3' })
})

describe('GET /versions — BOLA', () => {
  test('no session → 401 before any query', async () => {
    mockRequireEff.mockResolvedValue(UNAUTH)
    const res = await GET(get(), params('p1'))
    expect(res.status).toBe(401)
    expect(mockQueryRaw).not.toHaveBeenCalled()
  })

  test("EXPLOIT: another user's project → 404, history never read", async () => {
    mockRequireProjectAccess.mockResolvedValue(NOT_FOUND)
    const res = await GET(get(), params('victimProj'))
    expect(res.status).toBe(404)
    expect(mockEnsureCurrent).not.toHaveBeenCalled()
    expect(mockQueryRaw).not.toHaveBeenCalled()
  })

  test('owner → lists versions and flags which are activatable', async () => {
    mockQueryRaw.mockResolvedValue([
      { id: 'v3', seq: 3, label: 'Scan 3', is_current: true, pinned: false, node_count: 10, link_count: 5, created_at: new Date(), snapshot_bytes: null },
      { id: 'v2', seq: 2, label: 'Scan 2', is_current: false, pinned: false, node_count: 9, link_count: 4, created_at: new Date(), snapshot_bytes: 4096 },
      { id: 'v1', seq: 1, label: 'Scan 1', is_current: false, pinned: true, node_count: 8, link_count: 3, created_at: new Date(), snapshot_bytes: 0 },
    ])
    const res = await GET(get(), params('p1'))
    const body = await res.json()
    // The live/current version is never "activatable"; a bytes-less past one is not either (4A.6).
    expect(body.versions.map((v: { id: string; activatable: boolean }) => [v.id, v.activatable]))
      .toEqual([['v3', false], ['v2', true], ['v1', false]])
    expect(res.headers.get('Cache-Control')).toBe('private, no-cache')
  })
})

describe('POST /versions (save current as a version)', () => {
  test("EXPLOIT: another user's project → 404, no capture", async () => {
    mockRequireProjectAccess.mockResolvedValue(NOT_FOUND)
    const res = await POST(post(), params('victimProj'))
    expect(res.status).toBe(404)
    expect(mockCapture).not.toHaveBeenCalled()
  })

  test('refuses while an activation is swapping the graph', async () => {
    mockIsActivating.mockResolvedValue(true)
    const res = await POST(post(), params('p1'))
    expect(res.status).toBe(409)
    expect(mockCapture).not.toHaveBeenCalled()
  })

  test('refuses while a scan is rewriting the graph (Risk 1: no mid-write snapshot)', async () => {
    mockBusy.mockResolvedValue('a full recon scan is running')
    const res = await POST(post(), params('p1'))
    expect(res.status).toBe(409)
    expect(mockCapture).not.toHaveBeenCalled()
    expect(mockStore).not.toHaveBeenCalled()
  })

  test('rejects an invalid label before capturing anything', async () => {
    const res = await POST(post({ label: 'x'.repeat(500) }), params('p1'))
    expect(res.status).toBe(400)
    expect(mockCapture).not.toHaveBeenCalled()
  })

  test('an empty graph is not saved as a version', async () => {
    mockCapture.mockResolvedValue({ nodes: [], relationships: [], nodeCount: 0, linkCount: 0, summary: {} })
    const res = await POST(post(), params('p1'))
    expect(res.status).toBe(400)
    expect(mockStore).not.toHaveBeenCalled()
  })

  test('freezes the live graph and opens the next version for it', async () => {
    const res = await POST(post({ label: 'Before migration' }), params('p1'))
    expect(res.status).toBe(200)
    expect(mockStore).toHaveBeenCalledWith('vCur', expect.objectContaining({ nodeCount: 5 }))
    expect(mockUpdate).toHaveBeenCalledWith({ where: { id: 'vCur' }, data: { label: 'Before migration' } })
    // Demote + create go through the shared, collision-tolerant rotation.
    expect(mockRotate).toHaveBeenCalledWith('p1', 'vCur')
    const body = await res.json()
    expect(body.savedVersion.id).toBe('vCur')
    expect(body.currentVersion.id).toBe('vNew')
  })
})
