/**
 * Cross-route smoke test for the global row cap.
 *
 * rowCap.test.ts checks the function; this checks the thing that actually
 * reaches Neo4j. Every RedZone route is invoked with a stubbed session and the
 * emitted Cypher is inspected, which is the only level at which the two bugs
 * this file was written for are visible:
 *
 *   - a cap that floors to 0 emits `LIMIT 0` and empties every table,
 *   - a cap >= 1e21 emits `LIMIT 1e+21` and 500s every table.
 *
 * Neither is detectable from the handler's return value with an empty fixture,
 * because both produce a perfectly well-formed empty response.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/rowCapWiring.smoke.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const runCalls: string[] = []

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string) => {
      runCalls.push(cypher)
      return { records: [] }
    },
    close: async () => { /* no-op */ },
  }),
}))

const ROUTES: Record<string, { GET: (req: any) => Promise<Response> }> = {
  aiRisk: await import('./aiRisk/route'),
  aiSurface: await import('./aiSurface/route'),
  blastRadius: await import('./blastRadius/route'),
  dnsDrift: await import('./dnsDrift/route'),
  dnsEmail: await import('./dnsEmail/route'),
  graphql: await import('./graphql/route'),
  killChain: await import('./killChain/route'),
  netInitAccess: await import('./netInitAccess/route'),
  paramMatrix: await import('./paramMatrix/route'),
  routeExposure: await import('./routeExposure/route'),
  secrets: await import('./secrets/route'),
  sharedInfra: await import('./sharedInfra/route'),
  supplyChain: await import('./supplyChain/route'),
  supplyChainSca: await import('./supplyChainSca/route'),
  takeover: await import('./takeover/route'),
  threatIntel: await import('./threatIntel/route'),
  webCachePoison: await import('./webCachePoison/route'),
  webInitAccess: await import('./webInitAccess/route'),
}

const ROUTE_NAMES = Object.keys(ROUTES)

// dnsEmail is the one route with no LIMIT: it returns one row per Domain, so
// the set is bounded by the data model rather than by a cap.
const UNCAPPED = new Set(['dnsEmail'])

function makeRequest(projectId = 'p1'): any {
  return { nextUrl: new URL(`http://localhost:3000/api/analytics/redzone/x?projectId=${projectId}`) }
}

/** Every `LIMIT <token>` emitted by the last handler call. */
function emittedLimits(): string[] {
  return runCalls.flatMap(c => [...c.matchAll(/LIMIT\s+(\S+)/g)].map(m => m[1].replace(/`.*$/, '')))
}

beforeEach(() => {
  runCalls.length = 0
})

afterEach(() => {
  delete process.env.REDAMON_REDZONE_ROW_CAP
})

describe('every route emits a Cypher-parseable LIMIT', () => {
  test('the route list is non-trivial (guards the harness, not the app)', () => {
    expect(ROUTE_NAMES.length).toBeGreaterThan(15)
  })

  test.each(ROUTE_NAMES)('%s emits only plain positive integer LIMITs', async name => {
    const res = await ROUTES[name].GET(makeRequest())
    expect(res.status, `${name} did not return 200`).toBe(200)

    const limits = emittedLimits()
    if (UNCAPPED.has(name)) {
      expect(limits).toEqual([])
      return
    }
    expect(limits.length, `${name} emitted no LIMIT at all`).toBeGreaterThan(0)
    for (const lit of limits) {
      expect(lit, `${name} emitted "LIMIT ${lit}", which Cypher cannot parse`).toMatch(/^\d+$/)
      expect(Number(lit)).toBeGreaterThan(0)
      expect(Number.isSafeInteger(Number(lit))).toBe(true)
    }
  })

  test.each(ROUTE_NAMES.filter(n => !UNCAPPED.has(n)))(
    '%s uses the global cap, not a per-route one',
    async name => {
      await ROUTES[name].GET(makeRequest())
      for (const lit of emittedLimits()) expect(Number(lit)).toBe(200_000)
    },
  )
})

describe('the env override reaches every route', () => {
  // Proves rowCap() is read per request rather than captured at module load:
  // these route modules were imported at the top of this file, long before the
  // env var was set.
  test.each(ROUTE_NAMES.filter(n => !UNCAPPED.has(n)))('%s honours a lowered cap', async name => {
    process.env.REDAMON_REDZONE_ROW_CAP = '7'
    await ROUTES[name].GET(makeRequest())
    const limits = emittedLimits()
    expect(limits.length).toBeGreaterThan(0)
    for (const lit of limits) expect(Number(lit)).toBe(7)
  })

  // The two regressions, exercised through the real query text rather than
  // through rowCap()'s return value.
  test.each(['0.5', '0', '-3', 'lots', ''])(
    'a junk override (%j) never empties the tables with LIMIT 0',
    async raw => {
      process.env.REDAMON_REDZONE_ROW_CAP = raw
      await ROUTES.killChain.GET(makeRequest())
      for (const lit of emittedLimits()) expect(Number(lit)).toBe(200_000)
    },
  )

  test.each(['1e21', '999999999999999999999'])(
    'an absurd override (%j) never emits exponential notation',
    async raw => {
      process.env.REDAMON_REDZONE_ROW_CAP = raw
      await ROUTES.killChain.GET(makeRequest())
      for (const lit of emittedLimits()) {
        expect(lit).toMatch(/^\d+$/)
        expect(lit).not.toContain('e')
      }
    },
  )
})

describe('cap changes do not leak across sheets within one response', () => {
  // supplyChainSca is the only route that reads the cap into locals and reuses
  // it for both the query and the meta.truncated comparison, so a drift between
  // the two would mislabel a capped sheet as complete.
  test('supplyChainSca uses one consistent cap for all three sheets', async () => {
    process.env.REDAMON_REDZONE_ROW_CAP = '11'
    const res = await ROUTES.supplyChainSca.GET(makeRequest())
    expect(res.status).toBe(200)
    const limits = emittedLimits()
    expect(limits.length).toBeGreaterThanOrEqual(3)
    expect(new Set(limits.map(Number))).toEqual(new Set([11]))
  })

  test('an empty graph reports nothing truncated', async () => {
    const res = await ROUTES.supplyChainSca.GET(makeRequest())
    const body = await res.json()
    expect(body.meta.truncated).toEqual({ verdicts: false, packages: false, advisories: false })
  })
})
