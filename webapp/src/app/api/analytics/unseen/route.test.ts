/**
 * Route handler tests for the unseen-badge count endpoint.
 *
 * `./sources` is stubbed: what each tab's own route returns is covered by
 * sources.test.ts, and pulling seventeen real route modules in here would test
 * their Cypher rather than this route's fan-out, sanitising and seeding.
 *
 * Run: npx vitest run src/app/api/analytics/unseen/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const guardProject = vi.fn().mockResolvedValue(null)
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...args: unknown[]) => guardProject(...args) }))

const NOW = '2026-08-20T12:00:00.000Z'
const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let labelRows: Array<Record<string, unknown>> = []
let shouldThrow: Error | null = null
const closed = { count: 0 }

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      if (shouldThrow) throw shouldThrow
      if (cypher.includes('AS now')) return { records: [{ get: () => NOW }] }
      return { records: labelRows.map(row => ({ get: (key: string) => row[key] })) }
    },
    close: async () => { closed.count++ },
  }),
}))

/** Per-tab row counts the stubbed sources will report, and what was asked for. */
let routeCounts: Record<string, number> = {}
const sourceCalls: Array<{ tab: string; projectId: string; sinceMs: number }> = []
let inFlight = 0
let peakInFlight = 0

vi.mock('./sources', () => ({
  LABEL_TABS: ['nodeDetails', 'all', 'jsRecon'],
  ROUTE_TABS: ['dnsEmail', 'dnsDrift', 'secrets', 'takeover', 'webCachePoison', 'sharedInfra'],
  labelsForTab: (tab: string) => (tab === 'jsRecon' ? ['JsReconFinding'] : ['Domain', 'IP']),
  countUnseenRows: async (tab: string, projectId: string, sinceMs: number) => {
    sourceCalls.push({ tab, projectId, sinceMs })
    inFlight++
    peakInFlight = Math.max(peakInFlight, inFlight)
    await new Promise(r => setTimeout(r, 1))
    inFlight--
    return routeCounts[tab] ?? 0
  },
}))

const route = await import('./route')

function makeRequest(body: unknown): any {
  return { json: async () => body }
}

beforeEach(() => {
  runCalls.length = 0
  labelRows = []
  shouldThrow = null
  closed.count = 0
  routeCounts = {}
  sourceCalls.length = 0
  inFlight = 0
  peakInFlight = 0
  guardProject.mockClear().mockResolvedValue(null)
})

const T1 = '2026-08-01T00:00:00.000Z'
const allMarks = (since = T1) => ({
  nodeDetails: since, all: since, jsRecon: since,
  dnsEmail: since, dnsDrift: since, secrets: since,
  takeover: since, webCachePoison: since, sharedInfra: since,
})

describe('access', () => {
  test('a denied project short-circuits before any Cypher runs', async () => {
    guardProject.mockResolvedValue(new Response('nope', { status: 404 }))
    const res = await route.POST(makeRequest({ projectId: 'other', marks: { dnsEmail: T1 } }))
    expect(res.status).toBe(404)
    expect(runCalls).toHaveLength(0)
    expect(sourceCalls).toHaveLength(0)
  })

  test('a missing projectId is refused by the guard', async () => {
    await route.POST(makeRequest({ marks: {} }))
    expect(guardProject).toHaveBeenCalledWith('')
  })

  test('an unparseable body is a 400', async () => {
    const res = await route.POST({ json: async () => { throw new Error('bad') } } as any)
    expect(res.status).toBe(400)
  })
})

describe('watermarks', () => {
  test('no watermarks at all costs nothing and returns the clock to seed from', async () => {
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: {} }))
    expect(await res.json()).toEqual({ now: NOW, counts: {}, total: 0 })
    expect(runCalls.filter(c => !c.cypher.includes('AS now'))).toHaveLength(0)
    expect(sourceCalls).toHaveLength(0)
  })

  test('a watermark for an unknown tab is ignored', async () => {
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: { notATab: T1 } }))
    expect((await res.json()).counts).toEqual({})
  })

  test('an unparseable watermark is dropped rather than sent to datetime()', async () => {
    // `datetime('last tuesday')` throws in Cypher and would take every badge on
    // the page down with it, so one bad value must not poison the request.
    const res = await route.POST(
      makeRequest({ projectId: 'p1', marks: { dnsEmail: 'last tuesday', dnsDrift: T1 } }),
    )
    expect(sourceCalls.map(c => c.tab)).toEqual(['dnsDrift'])
    expect(Object.keys((await res.json()).counts)).toEqual(['dnsDrift'])
  })

  test('a non-string watermark is dropped', async () => {
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: { dnsEmail: 12345 } }))
    expect((await res.json()).counts).toEqual({})
  })

  test('each tab is measured from its own watermark', async () => {
    await route.POST(makeRequest({
      projectId: 'p1',
      marks: { dnsEmail: T1, dnsDrift: '2026-08-05T00:00:00.000Z' },
    }))
    const byTab = Object.fromEntries(sourceCalls.map(c => [c.tab, c.sinceMs]))
    expect(byTab.dnsEmail).toBe(Date.parse(T1))
    expect(byTab.dnsDrift).toBe(Date.parse('2026-08-05T00:00:00.000Z'))
  })
})

describe('counting', () => {
  test('a filtered tab reports what its own route would show, not a label count', async () => {
    // The regression this route was rewritten for: the graph gained four
    // Vulnerability nodes, and Web Cache Poisoning shows none of them.
    labelRows = [{ c: { low: 4, high: 0 } }]
    routeCounts = { webCachePoison: 0 }
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: allMarks() }))
    const body = await res.json()
    expect(body.counts.webCachePoison).toBe(0)
    expect(body.counts.all).toBe(4)
  })

  test('whole-graph tabs sum every label branch, unwrapping neo4j integers', async () => {
    labelRows = [{ c: { low: 3, high: 0 } }, { c: { low: 5, high: 0 } }]
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: allMarks() }))
    expect((await res.json()).counts.nodeDetails).toBe(8)
  })

  test('the label query is scoped to the project and the watermark', async () => {
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: allMarks() }))
    expect(res.status).toBe(200)
    const counting = runCalls.find(c => !c.cypher.includes('AS now'))!
    expect(counting.params.pid).toBe('p1')
    expect(counting.params.since).toBe(T1)
  })

  test('the bar total does not triple-count the whole graph', async () => {
    // Node Inspector and All Nodes are the SAME 10 nodes, and Secrets' 3 rows
    // are 3 of them. Summing the badges would say 23.
    labelRows = [{ c: { low: 10, high: 0 } }]
    routeCounts = { secrets: 3 }
    const marks = { nodeDetails: T1, all: T1, secrets: T1 }
    const body = await (await route.POST(makeRequest({ projectId: 'p1', marks }))).json()
    expect(body.counts).toEqual({ nodeDetails: 10, all: 10, secrets: 3 })
    expect(body.total).toBe(10)
  })

  test('the fan-out is bounded so it cannot drain the driver pool', async () => {
    await route.POST(makeRequest({ projectId: 'p1', marks: allMarks() }))
    expect(sourceCalls).toHaveLength(6)
    expect(peakInFlight).toBeLessThanOrEqual(5)
  })

  test('the clock comes from the graph, not the process', async () => {
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: { dnsEmail: T1 } }))
    expect((await res.json()).now).toBe(NOW)
  })

  test('a Cypher failure is a 500 and still closes the session', async () => {
    shouldThrow = new Error('boom')
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: { dnsEmail: T1 } }))
    expect(res.status).toBe(500)
    expect(closed.count).toBe(1)
  })
})
