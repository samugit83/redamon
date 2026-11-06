/** @vitest-environment node */
/**
 * A Subdomain written with DNS skipped carries status 'unverified' and no
 * RESOLVES_TO edge (plan 08.1). The report and Insights count a subdomain as
 * resolved by that edge, never by its status, so 'unverified' is never counted.
 * The status is shared with http_probe (it becomes an HTTP code later), which
 * is why it must not be the test.
 *
 * The Cypher itself runs against a real Neo4j in
 * subdomainResolvedCount.integration.test.ts.
 *
 * Run: npx vitest run src/lib/report/subdomainResolvedCount.test.ts
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

function int(n: number) { return { low: n, high: 0 } }

const SUBS: Record<string, unknown> = { total: int(4), resolved: int(1), uniqueIps: int(1) }
const queries: string[] = []

function respond(cypher: string) {
  queries.push(cypher)
  if (cypher.includes('AS uniqueIps') && cypher.includes(':Subdomain')) {
    return { records: [{ get: (k: string) => SUBS[k] }] }
  }
  return { records: [] }
}

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: async (cypher: string) => respond(cypher), close: async () => {} }),
}))

const { queryGraphOverview } = await import('./reportData')
const graphOverview = await import('@/app/api/analytics/graph-overview/route')

const subQuery = () => queries.find(q => q.includes('AS uniqueIps') && q.includes(':Subdomain'))!

function expectCountedByEdge(cypher: string) {
  // Only current forward DNS: a passive source's old address is not a resolution.
  expect(cypher).toContain('OPTIONAL MATCH (s)-[dnsr:RESOLVES_TO]->(i:IP) WHERE dnsr.source IS NULL')
  expect(cypher).toContain('count(DISTINCT CASE WHEN i IS NOT NULL THEN s END) AS resolved')
  expect(cypher).not.toMatch(/\bstatus\b/)
}

beforeEach(() => { queries.length = 0 })

describe('subdomains counted as resolved', () => {
  test('the report counts a RESOLVES_TO edge, not the status', async () => {
    const overview = await queryGraphOverview({ run: async (c: string) => respond(c) }, 'p1')
    expectCountedByEdge(subQuery())
    expect(overview.subdomainStats).toEqual({ total: 4, resolved: 1, uniqueIps: 1 })
  })

  test('Insights counts a RESOLVES_TO edge, not the status', async () => {
    const request = { nextUrl: new URL('http://localhost:3000/api/analytics/graph-overview?projectId=p1') }
    const body = await (await graphOverview.GET(request as never)).json()
    expectCountedByEdge(subQuery())
    expect(body.subdomainStats).toEqual({ total: 4, resolved: 1, uniqueIps: 1 })
  })
})
