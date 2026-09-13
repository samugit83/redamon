/**
 * BOLA / IDOR — GET /api/projects/[id]/delta.
 *
 * `from` and `to` are client-supplied version ids, so each must be proven to
 * belong to THIS project before its snapshot contents are read and returned —
 * otherwise the diff becomes a read primitive for another project's graph.
 *
 * Also pins the symmetry rule: `current` is read through the SAME capture query
 * as a snapshot, not through /api/graph, so the two sides are comparable.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  requireEff: vi.fn(),
  requireProjectAccess: vi.fn(),
  resolve: vi.fn(),
  capture: vi.fn(),
  load: vi.fn(),
  describeWriters: vi.fn(),
}))

vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.requireEff(),
  requireProjectAccess: (...a: unknown[]) => h.requireProjectAccess(...a),
}))
// scanVersionAccess is only partially mocked, so its real module (and therefore
// the Prisma client) still gets imported — stub the client so no engine loads.
vi.mock('@/lib/prisma', () => ({
  default: { scanVersion: { findUnique: vi.fn() }, $queryRaw: vi.fn() },
}))
vi.mock('@/lib/scanVersionAccess', async orig => ({
  ...(await orig<typeof import('@/lib/scanVersionAccess')>()),
  resolveVersionSelector: (...a: unknown[]) => h.resolve(...a),
}))
vi.mock('@/lib/scanSnapshot', async orig => ({
  ...(await orig<typeof import('@/lib/scanSnapshot')>()),
  captureGraphSnapshot: (...a: unknown[]) => h.capture(...a),
  loadSnapshot: (...a: unknown[]) => h.load(...a),
}))
vi.mock('@/lib/graphWriters', () => ({
  describeLiveGraphWriters: (...a: unknown[]) => h.describeWriters(...a),
}))

import { GET } from './route'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const UNAUTH = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const req = (qs: string) => new NextRequest(`http://x/api/projects/p1/delta?${qs}`)

const PAST = {
  id: 'v1', projectId: 'p1', seq: 1, label: 'Scan 1', isCurrent: false,
  pinned: false, nodeCount: 1, linkCount: 0, createdAt: new Date(), hasSnapshot: true,
}
const snap = (address: string) => ({
  nodes: [{ labels: ['IP'], properties: { address }, _exportId: 'n1' }],
  relationships: [],
})

beforeEach(() => {
  vi.clearAllMocks()
  h.describeWriters.mockResolvedValue(null)
  h.requireEff.mockResolvedValue({ userId: 'owner' })
  h.requireProjectAccess.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
  h.resolve.mockImplementation(async (_pid: string, sel: string | null) =>
    !sel || sel === 'current' ? { current: true } : PAST)
  h.load.mockResolvedValue(snap('10.0.0.1'))
  h.capture.mockResolvedValue({
    nodes: [{ labels: ['IP'], properties: { address: '10.0.0.2' }, _exportId: 'x1' }],
    relationships: [], nodeCount: 1, linkCount: 0, summary: {},
  })
})

describe('authorization', () => {
  test('no session → 401 before any read', async () => {
    h.requireEff.mockResolvedValue(UNAUTH)
    const res = await GET(req('from=v1&to=current'), params('p1'))
    expect(res.status).toBe(401)
    expect(h.load).not.toHaveBeenCalled()
    expect(h.capture).not.toHaveBeenCalled()
  })

  test("EXPLOIT: another user's project → 404 before any read", async () => {
    h.requireProjectAccess.mockResolvedValue(NOT_FOUND)
    const res = await GET(req('from=v1&to=current'), params('victimProj'))
    expect(res.status).toBe(404)
    expect(h.load).not.toHaveBeenCalled()
  })

  test("EXPLOIT: a `from` version from another project → 404, no snapshot read", async () => {
    h.resolve.mockImplementation(async (_pid: string, sel: string | null) =>
      sel === 'vOther' ? NOT_FOUND : { current: true })
    const res = await GET(req('from=vOther&to=current'), params('p1'))
    expect(res.status).toBe(404)
    expect(h.load).not.toHaveBeenCalled()
    expect(h.capture).not.toHaveBeenCalled()
  })

  test("EXPLOIT: a `to` version from another project → 404, no snapshot read", async () => {
    h.resolve.mockImplementation(async (_pid: string, sel: string | null) =>
      sel === 'vOther' ? NOT_FOUND : { current: true })
    const res = await GET(req('from=current&to=vOther'), params('p1'))
    expect(res.status).toBe(404)
    expect(h.load).not.toHaveBeenCalled()
  })
})

describe('payload sourcing', () => {
  test("`current` is captured with the SNAPSHOT query, never /api/graph", async () => {
    const res = await GET(req('from=v1&to=current'), params('p1'))
    expect(res.status).toBe(200)
    expect(h.capture).toHaveBeenCalledWith('p1')
    const body = await res.json()
    expect(body.to).toMatchObject({ versionId: 'current', isCurrent: true })
    expect(body.from).toMatchObject({ versionId: 'v1', label: 'Scan 1' })
  })

  test('computes the diff between the two sides', async () => {
    const res = await GET(req('from=v1&to=current'), params('p1'))
    const body = await res.json()
    expect(body.totals).toMatchObject({ added: 1, removed: 1, changed: 0 })
    expect(body.addedNodes[0].properties.address).toBe('10.0.0.2')
    expect(body.removedNodes[0].properties.address).toBe('10.0.0.1')
    expect(res.headers.get('Cache-Control')).toBe('private, no-cache')
  })

  test('a version with no bytes is reported, not silently compared as empty', async () => {
    h.load.mockResolvedValue(null)
    const res = await GET(req('from=v1&to=current'), params('p1'))
    expect(res.status).toBe(409)
    expect((await res.json()).emptySnapshot).toBe(true)
  })

  test('the graph overlay is opt-in', async () => {
    let body = await (await GET(req('from=v1&to=current'), params('p1'))).json()
    expect(body.overlay).toBeUndefined()
    body = await (await GET(req('from=v1&to=current&overlay=1'), params('p1'))).json()
    expect(body.overlay.nodes).toHaveLength(2)
  })

  test('missing selectors default both sides to current (a no-op diff)', async () => {
    const res = await GET(req(''), params('p1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.totals).toMatchObject({ added: 0, removed: 0, changed: 0 })
  })
})

describe('capturing the live graph waits for whoever is writing it', () => {
  // This route had no guard at all (X15). Capturing the live graph while
  // something is rewriting it produces a comparison against a state that never
  // existed, which is worse than refusing: the operator believes the diff.
  test('a live triage run refuses the capture rather than diffing mid-write', async () => {
    h.describeWriters.mockResolvedValue('a triage run is in progress')
    const res = await GET(req(''), params('p1'))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ graphBusy: true })
    expect(h.capture).not.toHaveBeenCalled()
  })

  test('comparing two stored snapshots does not need the live graph at all', async () => {
    h.describeWriters.mockResolvedValue('a full recon scan is running')
    h.resolve.mockResolvedValue(PAST)
    h.load.mockResolvedValue(snap('10.0.0.1'))
    const res = await GET(req('from=v1&to=v1'), params('p1'))
    expect(res.status).toBe(200)
  })
})
