/**
 * @vitest-environment node
 *
 * The Insights attack-surface and graph-overview routes count an endpoint known
 * only from an API specification apart from observed ones. A specification can
 * declare thousands of operations no tool ever saw; counted as surface they
 * inflated the endpoint charts, the risk gauge and the posture radar. Both
 * split on the predicate recon uses, so a node an earlier release declared
 * (no openapi_declared_only) counts as declared.
 *
 * Run: npx vitest run src/app/api/analytics/insightsDeclared.test.ts
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { DECLARED_ONLY } from '@/lib/declaredOnly'

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const queries: string[] = []
let rows: (cypher: string) => Record<string, unknown>[] = () => []

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string) => {
      queries.push(cypher)
      return { records: rows(cypher).map(row => ({ get: (k: string) => row[k] })) }
    },
    close: async () => {},
  }),
}))

const attackSurface = await import('./attack-surface/route')
const graphOverview = await import('./graph-overview/route')

const request = (path: string) =>
  ({ nextUrl: new URL(`http://localhost:3000/api/analytics/${path}?projectId=p1`) }) as never
const query = (marker: string) => queries.find(q => q.includes(marker))!

beforeEach(() => {
  queries.length = 0
  rows = () => []
})

describe('attack-surface: endpoints and parameters', () => {
  test('categories, types and parameters split on the declared-only predicate', async () => {
    rows = cypher => {
      if (cypher.includes('AS category') && cypher.includes('Endpoint')) return [{ category: 'api', count: 3, declared: 9998 }]
      if (cypher.includes('END AS type')) return [{ type: 'Static', count: 3, declared: 9998 }]
      if (cypher.includes('AS position')) return [{ position: 'query', total: 2, injectable: 1, declared: 40 }]
      return []
    }
    const body = await (await attackSurface.GET(request('attack-surface'))).json()

    for (const marker of ["COALESCE(e.category, 'other') AS category", 'END AS type', 'AS position']) {
      expect(query(marker), marker).toContain(`${DECLARED_ONLY('e')} AS declared`)
    }
    // The injectable count drives the risk gauge: a declared parameter is never injectable surface.
    expect(query('AS position')).toContain('count(CASE WHEN NOT declared AND p.is_injectable = true THEN 1 END) AS injectable')

    expect(body.endpointCategories).toEqual([{ category: 'api', count: 3, declared: 9998 }])
    expect(body.endpointTypes).toEqual([{ type: 'Static', count: 3, declared: 9998 }])
    expect(body.parameterAnalysis).toEqual([{ position: 'query', total: 2, injectable: 1, declared: 40 }])
  })
})

describe('graph-overview: endpoint coverage', () => {
  test('coverage counts observed endpoints and parameters, declared ones apart', async () => {
    rows = cypher => cypher.includes('AS baseUrls')
      ? [{ baseUrls: 1, endpoints: 7, parameters: 4, declaredEndpoints: 9999, declaredParameters: 13 }]
      : []
    const body = await (await graphOverview.GET(request('graph-overview'))).json()

    const q = query('AS baseUrls')
    expect(q).toContain(`${DECLARED_ONLY('e')} AS declared`)
    expect(q).toContain('count(DISTINCT CASE WHEN NOT declared THEN e END) AS endpoints')
    expect(q).toContain('count(DISTINCT CASE WHEN declared THEN p END) AS declaredParameters')
    expect(body.endpointCoverage).toEqual(
      { baseUrls: 1, endpoints: 7, parameters: 4, declaredEndpoints: 9999, declaredParameters: 13 })
  })
})
