/**
 * Integration test: the Cypher every RedZone route actually generates must
 * PARSE and PLAN on a real Neo4j with the global row cap interpolated into it.
 *
 * The unit and smoke tests both assert against a regex. A regex cannot tell you
 * that Neo4j accepts `LIMIT 200000`, and this exact class of bug is invisible
 * to a mocked session: `LIMIT 1e+21` is a perfectly well-formed JS string and
 * fails only at the database, with
 *
 *   Invalid input. '1e+21' is not a valid value. Must be a non-negative integer.
 *
 * which would have turned all 16 tables into 500s at once.
 *
 * EXPLAIN, not a real run: it forces full parse + semantic checking + planning
 * while touching no data, so this is safe against a populated graph and fast.
 *
 * Requirements: Neo4j reachable on bolt (docker compose up -d neo4j) with
 * NEO4J_PASSWORD in the environment. Skips cleanly when absent, so it never
 * turns a laptop or CI run red.
 *
 * Run: set -a; . ./.env; set +a; \
 *      npx vitest run src/app/api/analytics/redzone/rowCapCypher.integration.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, afterAll, vi } from 'vitest'
import neo4j from 'neo4j-driver'

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const captured: Array<{ cypher: string; params: Record<string, unknown> }> = []

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string, params: Record<string, unknown> = {}) => {
      captured.push({ cypher, params })
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

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

const driver = PASSWORD ? neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD)) : null
let live = false
if (driver) {
  try {
    await driver.verifyConnectivity()
    live = true
  } catch {
    live = false
  }
}

afterAll(async () => {
  await driver?.close()
})

async function explain(cypher: string, params: Record<string, unknown>): Promise<void> {
  const session = driver!.session()
  try {
    await session.run(`EXPLAIN ${cypher}`, params)
  } finally {
    await session.close()
  }
}

/** Drive one route through the mock and hand back the Cypher it produced. */
async function cypherFor(name: string) {
  captured.length = 0
  const res = await ROUTES[name].GET({
    nextUrl: new URL(`http://localhost:3000/api/analytics/redzone/${name}?projectId=itest-nonexistent`),
  })
  expect(res.status).toBe(200)
  return [...captured]
}

describe.skipIf(!live)('generated Cypher parses on a real Neo4j', () => {
  test('the harness is actually connected (guards against a silent skip)', async () => {
    const session = driver!.session()
    try {
      const r = await session.run('RETURN 1 AS ok')
      expect(r.records[0].get('ok').toNumber?.() ?? r.records[0].get('ok')).toBe(1)
    } finally {
      await session.close()
    }
  })

  test.each(Object.keys(ROUTES))('%s: every query plans with the cap inlined', async name => {
    const queries = await cypherFor(name)
    expect(queries.length, `${name} issued no queries`).toBeGreaterThan(0)
    for (const { cypher, params } of queries) {
      await expect(
        explain(cypher, params),
        `${name} produced Cypher Neo4j cannot plan:\n${cypher}`,
      ).resolves.toBeUndefined()
    }
  })

  // A mutation check showed the cases above pass under BOTH the fixed and the
  // buggy rowCap(), because they only ever exercise the default cap. These
  // drive the hostile operator inputs all the way through a real route into a
  // real planner, which is the only place the two bugs were ever observable
  // together: a bad cap must still produce Cypher that PLANS (rules out
  // `LIMIT 1e+21`) and still SELECTS rows (rules out `LIMIT 0`).
  test.each(['0.5', '0', '-3', '1e21', '999999999999999999999', 'lots', ''])(
    'a hostile override (%j) still yields plannable, non-empty-by-construction Cypher',
    async raw => {
      process.env.REDAMON_REDZONE_ROW_CAP = raw
      try {
        const queries = await cypherFor('killChain')
        expect(queries.length).toBeGreaterThan(0)
        for (const { cypher, params } of queries) {
          const limits = [...cypher.matchAll(/LIMIT\s+(\d+)/g)].map(m => Number(m[1]))
          expect(limits.length, `no integer LIMIT in:\n${cypher}`).toBeGreaterThan(0)
          for (const n of limits) expect(n).toBeGreaterThan(0)
          await expect(
            explain(cypher, params),
            `override ${JSON.stringify(raw)} produced unplannable Cypher:\n${cypher}`,
          ).resolves.toBeUndefined()
        }
      } finally {
        delete process.env.REDAMON_REDZONE_ROW_CAP
      }
    },
  )

  // Pins the failure mode rather than trusting the comment above it: if a
  // future refactor lets an exponential or fractional value reach the query,
  // this is the error it will produce.
  test('Neo4j rejects the exponential literal the cap logic guards against', async () => {
    await expect(explain('MATCH (n) RETURN n LIMIT 1e+21', {})).rejects.toThrow(
      /not a valid value|non-negative integer|Invalid input/i,
    )
  })

  test('Neo4j rejects a fractional LIMIT', async () => {
    await expect(explain('MATCH (n) RETURN n LIMIT 1.5', {})).rejects.toThrow(
      /not a valid value|non-negative integer|Invalid input/i,
    )
  })

  // LIMIT 0 is the quiet one: it is perfectly valid Cypher and returns nothing,
  // which is why the '0.5' -> LIMIT 0 bug could not have been caught by asking
  // the database whether the query was legal.
  test('LIMIT 0 is valid Cypher and returns nothing, hence the guard in rowCap()', async () => {
    const session = driver!.session()
    try {
      const r = await session.run('MATCH (n) RETURN n LIMIT 0')
      expect(r.records).toHaveLength(0)
    } finally {
      await session.close()
    }
  })
})

// Fails loudly if the suite silently skipped because the stack was down, but
// only when the caller explicitly demanded a live run.
describe.skipIf(!process.env.REDZONE_REQUIRE_LIVE)('live-stack requirement', () => {
  test('Neo4j was reachable', () => {
    expect(live, `could not reach Neo4j at ${URI}`).toBe(true)
  })
})
