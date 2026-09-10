/**
 * Scan Timeline — snapshot capture / storage / render unit tests.
 *
 * Covers the load-bearing guarantees of Step 1:
 *  - capture reads the graph in EXPORT fidelity and EXCLUDES agent session nodes (F1)
 *  - gzip round-trip is lossless (a snapshot must be restorable)
 *  - the size guard refuses (and does not persist) an oversized snapshot
 *  - the render conversion produces the same {nodes, links} shape as the live path
 *  - the backfill establishes exactly one current version, and self-heals a
 *    project whose rows exist but none is current (crashed activation)
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { gunzipSync } from 'zlib'

const mockRun = vi.fn()
const mockClose = vi.fn()
const prismaMock = vi.hoisted(() => ({
  scanVersion: {
    update: vi.fn(),
    findUnique: vi.fn(),
    findFirst: vi.fn(),
    create: vi.fn(),
  },
}))

vi.mock('@/lib/prisma', () => ({ default: prismaMock }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => mockRun(...a), close: mockClose }),
}))

import {
  captureGraphSnapshot,
  storeSnapshot,
  loadSnapshot,
  serializeSnapshot,
  deserializeSnapshot,
  snapshotToGraphPayload,
  functionalLabel,
  snapshotNodeIsMuted,
  summarizeGraphPayload,
  defaultVersionLabel,
  ensureCurrentVersion,
  withSnapshotSlot,
  SESSION_LABELS,
  SnapshotTooLargeError,
  snapshotMaxBytes,
} from './scanSnapshot'

/** Build a fake neo4j record whose get() reads from a plain object. */
function rec(fields: Record<string, unknown>) {
  return { keys: Object.keys(fields), get: (k: string) => fields[k] }
}

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.SCAN_SNAPSHOT_MAX_BYTES
})

afterEach(() => {
  delete process.env.SCAN_SNAPSHOT_MAX_BYTES
})

describe('suppressed findings in a snapshot', () => {
  // The two halves pull in opposite directions and both matter:
  // the STORED snapshot must keep `:Muted` (or export/import/version-activate
  // silently unmutes everything), while the RENDERED payload must drop it (the
  // graph screen and Recon Delta must never show a suppressed finding).
  const muted = () => rec({
    labels: ['Vulnerability', 'Muted'],
    props: { id: 'v-muted', project_id: 'p1', muted: true },
    eid: 'em',
  })
  const plain = () => rec({
    labels: ['Vulnerability'],
    props: { id: 'v-real', project_id: 'p1' },
    eid: 'ev',
  })

  test('capture KEEPS the Muted label so mute survives export and import', async () => {
    mockRun
      .mockResolvedValueOnce({ records: [muted(), plain()] })
      .mockResolvedValueOnce({ records: [] })

    const snap = await captureGraphSnapshot('p1')

    const stored = snap.nodes.find(n => n.properties.id === 'v-muted')!
    expect(stored.labels).toContain('Muted')
    expect(stored.labels).toContain('Vulnerability')
    expect(snap.nodeCount).toBe(2)
  })

  test('capture counts a muted node under its real type, never "Muted"', async () => {
    // labels[0] is not ordered by Neo4j, so a naive summary can report "Muted"
    // as if it were a node type.
    mockRun
      .mockResolvedValueOnce({ records: [muted(), plain()] })
      .mockResolvedValueOnce({ records: [] })

    const snap = await captureGraphSnapshot('p1')

    expect(snap.summary).toEqual({ Vulnerability: 2 })
    expect(snap.summary.Muted).toBeUndefined()
  })

  test('the rendered payload drops muted nodes and types the rest functionally', async () => {
    const payload = snapshotToGraphPayload({
      nodes: [
        { labels: ['Muted', 'Vulnerability'], properties: { id: 'v-muted' }, _exportId: 'x1' },
        { labels: ['Vulnerability'], properties: { id: 'v-real' }, _exportId: 'x2' },
      ],
      relationships: [],
    } as never)

    expect(payload.nodes.map(n => n.properties.id)).toEqual(['v-real'])
    expect(payload.nodes[0].type).toBe('Vulnerability')
  })

  test('a link to a muted node is dropped with it, leaving no dangling edge', async () => {
    const payload = snapshotToGraphPayload({
      nodes: [
        { labels: ['IP'], properties: { address: '10.0.0.1' }, _exportId: 'ip' },
        { labels: ['Vulnerability', 'Muted'], properties: { id: 'v' }, _exportId: 'vm' },
      ],
      relationships: [
        { startExportId: 'ip', endExportId: 'vm', type: 'HAS_VULNERABILITY', properties: {} },
      ],
    } as never)

    expect(payload.nodes).toHaveLength(1)
    expect(payload.links).toEqual([])
  })

  test('functionalLabel ignores Muted wherever it sits in the array', () => {
    expect(functionalLabel(['Vulnerability', 'Muted'])).toBe('Vulnerability')
    expect(functionalLabel(['Muted', 'Vulnerability'])).toBe('Vulnerability')
    expect(snapshotNodeIsMuted(['Muted', 'Secret'])).toBe(true)
    expect(snapshotNodeIsMuted(['Secret'])).toBe(false)
  })
})

describe('captureGraphSnapshot', () => {
  beforeEach(() => {
    mockRun
      .mockResolvedValueOnce({
        records: [
          rec({ labels: ['Subdomain'], props: { name: 'a.x.tld', project_id: 'p1', user_id: 'u1' }, eid: 'e1' }),
          rec({ labels: ['IP'], props: { address: '10.0.0.1', project_id: 'p1' }, eid: 'e2' }),
          rec({ labels: ['Port'], props: { number: { low: 443, high: 0 }, protocol: 'tcp', project_id: 'p1' }, eid: 'e3' }),
        ],
      })
      .mockResolvedValueOnce({
        records: [
          rec({ startId: 'e1', endId: 'e2', relType: 'RESOLVES_TO', relProps: {} }),
          rec({ startId: 'e2', endId: 'e3', relType: 'HAS_PORT', relProps: { seen: { low: 2, high: 0 } } }),
          // Endpoint outside the captured node set (e.g. a global CVE node or an
          // excluded chain node) — must be dropped, exactly like on export.
          rec({ startId: 'e3', endId: 'eOTHER', relType: 'RUNS_SERVICE', relProps: {} }),
        ],
      })
  })

  test('excludes agent session labels in the node query (F1)', async () => {
    await captureGraphSnapshot('p1')
    const [cypher, params] = mockRun.mock.calls[0]
    expect(cypher).toContain('NONE(l IN labels(n) WHERE l IN $sessionLabels)')
    expect(params.sessionLabels).toEqual([...SESSION_LABELS])
    expect(params.pid).toBe('p1')
  })

  test('captures export-fidelity nodes + relationships, counts and per-type summary', async () => {
    const snap = await captureGraphSnapshot('p1')

    expect(snap.nodeCount).toBe(3)
    expect(snap.linkCount).toBe(2) // the dangling relationship is filtered out
    expect(snap.summary).toEqual({ Subdomain: 1, IP: 1, Port: 1 })

    // Full properties are kept, including tenant fields (needed for restore).
    const sub = snap.nodes.find(n => n.labels[0] === 'Subdomain')!
    expect(sub.properties).toEqual({ name: 'a.x.tld', project_id: 'p1', user_id: 'u1' })
    // Neo4j Integer objects are flattened.
    const port = snap.nodes.find(n => n.labels[0] === 'Port')!
    expect(port.properties.number).toBe(443)

    // Relationships reference nodes by stable export id.
    const ids = new Set(snap.nodes.map(n => n._exportId))
    for (const r of snap.relationships) {
      expect(ids.has(r.startExportId)).toBe(true)
      expect(ids.has(r.endExportId)).toBe(true)
    }
    expect(snap.relationships.map(r => r.type).sort()).toEqual(['HAS_PORT', 'RESOLVES_TO'])
    expect(snap.relationships.find(r => r.type === 'HAS_PORT')!.properties.seen).toBe(2)
  })

  test('closes the Neo4j session even when the query throws', async () => {
    mockRun.mockReset()
    mockRun.mockRejectedValue(new Error('neo4j down'))
    await expect(captureGraphSnapshot('p1')).rejects.toThrow('neo4j down')
    expect(mockClose).toHaveBeenCalled()
  })
})

describe('snapshot serialization', () => {
  const payload = {
    nodes: [
      { labels: ['Subdomain'], properties: { name: 'a.x.tld' }, _exportId: 'n1' },
      { labels: ['IP'], properties: { address: '10.0.0.1' }, _exportId: 'n2' },
    ],
    relationships: [
      { startExportId: 'n1', endExportId: 'n2', type: 'RESOLVES_TO', properties: { via: 'dns' } },
    ],
  }

  test('gzip round-trip is lossless', () => {
    const gz = serializeSnapshot(payload)
    expect(gz.length).toBeGreaterThan(0)
    expect(deserializeSnapshot(gz)).toEqual(payload)
    // Actually gzip, not raw JSON.
    expect(JSON.parse(gunzipSync(gz).toString())).toEqual(payload)
  })

  test('deserialize tolerates a payload missing either collection', () => {
    const gz = serializeSnapshot({ nodes: payload.nodes, relationships: [] })
    const back = deserializeSnapshot(gz)
    expect(back.relationships).toEqual([])
    expect(back.nodes).toHaveLength(2)
  })

  test('storeSnapshot persists bytes + counts + summary', async () => {
    prismaMock.scanVersion.update.mockResolvedValue({})
    const res = await storeSnapshot('v1', { ...payload, nodeCount: 2, linkCount: 1, summary: { Subdomain: 1, IP: 1 } })
    expect(res.bytes).toBeGreaterThan(0)
    const arg = prismaMock.scanVersion.update.mock.calls[0][0]
    expect(arg.where).toEqual({ id: 'v1' })
    expect(arg.data.nodeCount).toBe(2)
    expect(arg.data.linkCount).toBe(1)
    expect(arg.data.summary).toEqual({ Subdomain: 1, IP: 1 })
    expect(deserializeSnapshot(arg.data.snapshot)).toEqual(payload)
  })

  test('size guard refuses and does NOT persist an oversized snapshot', async () => {
    process.env.SCAN_SNAPSHOT_MAX_BYTES = '10'
    await expect(
      storeSnapshot('v1', { ...payload, nodeCount: 2, linkCount: 1, summary: {} })
    ).rejects.toBeInstanceOf(SnapshotTooLargeError)
    expect(prismaMock.scanVersion.update).not.toHaveBeenCalled()
  })

  test('snapshotMaxBytes falls back to a sane default on garbage config', () => {
    process.env.SCAN_SNAPSHOT_MAX_BYTES = 'not-a-number'
    expect(snapshotMaxBytes()).toBe(128 * 1024 * 1024)
    process.env.SCAN_SNAPSHOT_MAX_BYTES = '0'
    expect(snapshotMaxBytes()).toBe(128 * 1024 * 1024)
  })

  test('loadSnapshot returns null for a version with no bytes (legacy / live)', async () => {
    prismaMock.scanVersion.findUnique.mockResolvedValue({ snapshot: null })
    expect(await loadSnapshot('v1')).toBeNull()
    prismaMock.scanVersion.findUnique.mockResolvedValue(null)
    expect(await loadSnapshot('missing')).toBeNull()
  })

  test('loadSnapshot gunzips stored bytes', async () => {
    prismaMock.scanVersion.findUnique.mockResolvedValue({ snapshot: serializeSnapshot(payload) })
    expect(await loadSnapshot('v1')).toEqual(payload)
  })
})

describe('snapshotToGraphPayload', () => {
  test('produces the live render shape with stable ids and named nodes', () => {
    const out = snapshotToGraphPayload({
      nodes: [
        { labels: ['Subdomain'], properties: { name: 'a.x.tld' }, _exportId: 'n1' },
        { labels: ['Port'], properties: { number: 443, protocol: 'tcp' }, _exportId: 'n2' },
      ],
      relationships: [
        { startExportId: 'n1', endExportId: 'n2', type: 'HAS_PORT', properties: {} },
      ],
    })
    expect(out.nodes).toEqual([
      { id: 'n1', name: 'a.x.tld', type: 'Subdomain', properties: { name: 'a.x.tld' } },
      { id: 'n2', name: '443/tcp', type: 'Port', properties: { number: 443, protocol: 'tcp' } },
    ])
    expect(out.links).toEqual([{ source: 'n1', target: 'n2', type: 'HAS_PORT' }])
  })

  test('drops links whose endpoints are not in the node set (no dangling refs)', () => {
    const out = snapshotToGraphPayload({
      nodes: [{ labels: ['IP'], properties: { address: '1.1.1.1' }, _exportId: 'n1' }],
      relationships: [{ startExportId: 'n1', endExportId: 'gone', type: 'X', properties: {} }],
    })
    expect(out.links).toEqual([])
  })

  test('unlabeled nodes fall back to Unknown', () => {
    const out = snapshotToGraphPayload({
      nodes: [{ labels: [], properties: {}, _exportId: 'n1' }],
      relationships: [],
    })
    expect(out.nodes[0].type).toBe('Unknown')
  })

  test('summarizeGraphPayload counts by rendered type', () => {
    expect(summarizeGraphPayload({
      nodes: [
        { id: '1', name: 'a', type: 'IP', properties: {} },
        { id: '2', name: 'b', type: 'IP', properties: {} },
        { id: '3', name: 'c', type: 'Port', properties: {} },
      ],
      links: [],
    })).toEqual({ IP: 2, Port: 1 })
  })
})

describe('defaultVersionLabel', () => {
  test('renders seq + UTC timestamp', () => {
    expect(defaultVersionLabel(3, new Date('2026-07-30T14:30:00Z')))
      .toBe('Scan 3 - 2026-07-30 14:30 UTC')
  })
})

describe('ensureCurrentVersion (backfill)', () => {
  test('returns the existing current version without creating one', async () => {
    prismaMock.scanVersion.findFirst.mockResolvedValueOnce({ id: 'v9', seq: 4, isCurrent: true })
    const v = await ensureCurrentVersion('p1')
    expect(v.id).toBe('v9')
    expect(prismaMock.scanVersion.create).not.toHaveBeenCalled()
  })

  test('creates seq=1 with snapshot=null for a pre-feature project', async () => {
    prismaMock.scanVersion.findFirst.mockResolvedValueOnce(null).mockResolvedValueOnce(null)
    prismaMock.scanVersion.create.mockResolvedValue({ id: 'v1', seq: 1, isCurrent: true })
    const v = await ensureCurrentVersion('p1')
    expect(v.id).toBe('v1')
    const data = prismaMock.scanVersion.create.mock.calls[0][0].data
    expect(data).toMatchObject({ projectId: 'p1', seq: 1, isCurrent: true, snapshot: null })
  })

  test('adopts the highest seq when rows exist but none is current (crashed activation)', async () => {
    prismaMock.scanVersion.findFirst
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ id: 'v7', seq: 7, isCurrent: false })
    prismaMock.scanVersion.update.mockResolvedValue({})
    const v = await ensureCurrentVersion('p1')
    expect(v).toMatchObject({ id: 'v7', isCurrent: true })
    expect(prismaMock.scanVersion.update).toHaveBeenCalledWith({
      where: { id: 'v7' }, data: { isCurrent: true },
    })
    expect(prismaMock.scanVersion.create).not.toHaveBeenCalled()
  })

  test('IDEMPOTENT: a second call creates nothing once a current version exists', async () => {
    prismaMock.scanVersion.findFirst.mockResolvedValueOnce(null).mockResolvedValueOnce(null)
    prismaMock.scanVersion.create.mockResolvedValue({ id: 'v1', seq: 1, isCurrent: true })
    const first = await ensureCurrentVersion('p1')

    prismaMock.scanVersion.create.mockClear()
    prismaMock.scanVersion.findFirst.mockResolvedValueOnce({ id: 'v1', seq: 1, isCurrent: true })
    const second = await ensureCurrentVersion('p1')

    expect(second.id).toBe(first.id)
    expect(prismaMock.scanVersion.create).not.toHaveBeenCalled()
  })

  test('a create race resolves to the winner row rather than throwing', async () => {
    prismaMock.scanVersion.findFirst
      .mockResolvedValueOnce(null)          // no current
      .mockResolvedValueOnce(null)          // no rows at all
      .mockResolvedValueOnce({ id: 'vWin', seq: 1, isCurrent: true })
    prismaMock.scanVersion.create.mockRejectedValue(new Error('unique constraint'))
    const v = await ensureCurrentVersion('p1')
    expect(v.id).toBe('vWin')
  })
})

describe('withSnapshotSlot (F5 concurrency cap)', () => {
  test('serializes work beyond the configured concurrency', async () => {
    process.env.SCAN_SNAPSHOT_MAX_CONCURRENCY = '1'
    let peak = 0
    let inFlight = 0
    const task = async () => withSnapshotSlot(async () => {
      inFlight += 1
      peak = Math.max(peak, inFlight)
      await new Promise(r => setTimeout(r, 5))
      inFlight -= 1
    })
    await Promise.all([task(), task(), task()])
    expect(peak).toBe(1)
    delete process.env.SCAN_SNAPSHOT_MAX_CONCURRENCY
  })

  test('a caller arriving mid-handoff cannot push past the cap', async () => {
    // Regression: with an `if` guard instead of a `while`, a caller that arrives
    // in the microtask gap between "slot released" and "waiter resumed" takes the
    // free slot, and then the waiter ALSO increments — two bodies run under a cap
    // of one. Reproduced deterministically by stepping the microtask queue.
    process.env.SCAN_SNAPSHOT_MAX_CONCURRENCY = '1'
    let peak = 0
    let inFlight = 0
    const releases: Array<() => void> = []
    const body = () => {
      let release!: () => void
      const hold = new Promise<void>(r => { release = r })
      releases.push(release)
      return async () => {
        inFlight += 1
        peak = Math.max(peak, inFlight)
        await hold
        inFlight -= 1
      }
    }

    const a = withSnapshotSlot(body())   // A holds the only slot
    const b = withSnapshotSlot(body())   // B queues behind it
    releases[0]()                        // release A

    // Step to the tick where A has released but B has not yet resumed.
    for (let i = 0; i < 2; i++) await Promise.resolve()
    const c = withSnapshotSlot(body())   // C arrives exactly in that gap
    for (let i = 0; i < 4; i++) await Promise.resolve()

    expect(peak).toBe(1)

    // Never leak slots: the semaphore is module state shared with later tests.
    releases.slice(1).forEach(r => r())
    await Promise.all([a, b, c])
    delete process.env.SCAN_SNAPSHOT_MAX_CONCURRENCY
  })

  test('releases the slot when the body throws', async () => {
    process.env.SCAN_SNAPSHOT_MAX_CONCURRENCY = '1'
    await expect(withSnapshotSlot(async () => { throw new Error('boom') })).rejects.toThrow('boom')
    // A subsequent acquisition must not deadlock.
    await expect(withSnapshotSlot(async () => 'ok')).resolves.toBe('ok')
    delete process.env.SCAN_SNAPSHOT_MAX_CONCURRENCY
  })
})
