/** @vitest-environment node */
/**
 * IP-mode projects showed IPv4 0 / IPv6 0 beside a non-zero IP total: the
 * IP-mode writer stored IP.version as 'v4' / 'v6', every other writer as
 * 'ipv4' / 'ipv6', and the report and Insights counted only the long spelling.
 * Graphs written before the writer fix, and scan versions restored from them,
 * keep the short one, so both readers count both.
 *
 * The Cypher itself runs against a real Neo4j in
 * ipVersionCounts.integration.test.ts.
 *
 * Run: npx vitest run src/lib/report/ipVersionCounts.test.ts
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

function int(n: number) { return { low: n, high: 0 } }

const INFRA: Record<string, unknown> = {
  total: int(5), ipv4: int(3), ipv6: int(2), cdnCount: int(0), uniqueAsns: int(0), uniqueCdns: int(0),
}
const queries: string[] = []

function respond(cypher: string) {
  queries.push(cypher)
  if (cypher.includes('AS uniqueCdns')) return { records: [{ get: (k: string) => INFRA[k] }] }
  return { records: [] }
}

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: async (cypher: string) => respond(cypher), close: async () => {} }),
}))

const { queryGraphOverview } = await import('./reportData')
const graphOverview = await import('@/app/api/analytics/graph-overview/route')

const IPV4 = "ip.version IN ['ipv4', 'v4']"
const IPV6 = "ip.version IN ['ipv6', 'v6']"
const infraQuery = () => queries.find(q => q.includes('AS uniqueCdns'))!

beforeEach(() => { queries.length = 0 })

describe('the report: IPv4 / IPv6 counts', () => {
  test('count the IP-mode spelling as well', async () => {
    const overview = await queryGraphOverview({ run: async (c: string) => respond(c) }, 'p1')
    expect(infraQuery()).toContain(`count(CASE WHEN ${IPV4} THEN 1 END) AS ipv4`)
    expect(infraQuery()).toContain(`count(CASE WHEN ${IPV6} THEN 1 END) AS ipv6`)
    expect(infraQuery()).not.toContain("ip.version = 'ipv4'")
    expect(overview.infrastructureStats).toMatchObject({ totalIps: 5, ipv4: 3, ipv6: 2 })
  })
})

describe('Insights graph overview: IPv4 / IPv6 counts', () => {
  test('count the IP-mode spelling as well', async () => {
    const request = { nextUrl: new URL('http://localhost:3000/api/analytics/graph-overview?projectId=p1') }
    const body = await (await graphOverview.GET(request as never)).json()
    expect(infraQuery()).toContain(`count(CASE WHEN ${IPV4} THEN 1 END) AS ipv4`)
    expect(infraQuery()).toContain(`count(CASE WHEN ${IPV6} THEN 1 END) AS ipv6`)
    expect(infraQuery()).not.toContain("ip.version = 'ipv4'")
    expect(body.infrastructureStats).toMatchObject({ totalIps: 5, ipv4: 3, ipv6: 2 })
  })
})
