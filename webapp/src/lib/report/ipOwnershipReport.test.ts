/** @vitest-environment node */
/**
 * The report's IP tables carry the IP attribution tag (plan 11.4).
 *
 * The IP Target Map gains an Ownership column: Shared edge, Dedicated or
 * Unknown, and an EMPTY cell for an IP written before the step existed, never
 * "Unknown": no run looked. The Subdomain Resolution Map names a shared edge
 * or a dedicated address beside the IP.
 *
 * Run: npx vitest run src/lib/report/ipOwnershipReport.test.ts
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: async () => ({ records: [] }), close: async () => {} }),
}))

const { queryGraphOverview } = await import('./reportData')
const { renderScope } = await import('./reportTemplate')
type ReportData = import('./reportData').ReportData

function int(n: number) { return { low: n, high: 0 } }
function rec(values: Record<string, unknown>) { return { get: (k: string) => values[k] } }

const IP_ROWS = [
  rec({ ip: '198.51.100.20', version: 'ipv4', isCdn: true, cdnName: 'cloudflare', asn: 'AS13335',
        ownership: 'shared_edge', hostnames: [], openPorts: int(2) }),
  rec({ ip: '198.51.100.21', version: 'ipv4', isCdn: false, cdnName: null, asn: null,
        ownership: 'dedicated', hostnames: ['www.example.com'], openPorts: int(1) }),
  rec({ ip: '198.51.100.22', version: 'ipv4', isCdn: false, cdnName: null, asn: null,
        ownership: null, hostnames: [], openPorts: int(0) }),
]
const SUB_ROWS = [
  rec({ subdomain: 'www.example.com', openPorts: int(1), ips: [
    { address: '198.51.100.20', version: 'ipv4', isCdn: true, cdnName: 'cloudflare', ownership: 'shared_edge' },
    { address: '198.51.100.21', version: 'ipv4', isCdn: false, cdnName: null, ownership: 'unknown' },
  ] }),
]

const queries: string[] = []
const session = {
  run: async (cypher: string) => {
    queries.push(cypher)
    if (cypher.includes('collect(DISTINCT s.name) AS hostnames')) return { records: IP_ROWS }
    if (cypher.includes('RETURN s.name AS subdomain')) return { records: SUB_ROWS }
    return { records: [] }
  },
}

describe('the report data', () => {
  test('both IP queries read the tag', async () => {
    const overview = await queryGraphOverview(session, 'p1')
    expect(queries.find(q => q.includes('collect(DISTINCT s.name) AS hostnames'))).toContain('ip.ownership AS ownership')
    expect(queries.find(q => q.includes('RETURN s.name AS subdomain'))).toContain('ownership: ip.ownership')
    expect(overview.ipMappings.map(m => m.ownership)).toEqual(['shared_edge', 'dedicated', null])
    expect(overview.subdomainMappings[0].ips.map(i => i.ownership)).toEqual(['shared_edge', 'unknown'])
  })
})

describe('the rendered report', () => {
  async function html(ipMode: boolean) {
    const overview = await queryGraphOverview(session, 'p1')
    const data = {
      project: { ipMode, targetIps: ipMode ? ['198.51.100.0/24'] : [], targetDomain: 'example.com',
                 stealthMode: false },
      graphOverview: {
        totalNodes: 0, suppressedRules: [], judged: { personFalsePositive: 0, resolved: 0, aiFlagged: 0 },
        subdomainStats: { total: 1, resolved: 1, uniqueIps: 2 },
        infrastructureStats: { totalIps: 3 },
        endpointCoverage: { baseUrls: 0, endpoints: 0, parameters: 0 },
        ipMappings: overview.ipMappings,
        subdomainMappings: overview.subdomainMappings,
      },
    } as unknown as ReportData
    return renderScope(data)
  }

  test('the IP Target Map has an Ownership column, empty for an IP never attributed', async () => {
    const page = await html(true)
    const table = page.slice(page.indexOf('IP Target Map'), page.indexOf('</table>', page.indexOf('IP Target Map')))
    expect(table).toContain('<th>Ownership</th>')
    const rows = table.split('<tr>').slice(2)
    expect(rows).toHaveLength(3)
    expect(rows[0]).toContain('Shared edge')
    expect(rows[1]).toContain('Dedicated')
    expect(rows[2]).not.toMatch(/Unknown|Shared edge|Dedicated/)
  })

  test('the Subdomain Resolution Map names a shared edge, and says nothing of an unknown', async () => {
    const page = await html(false)
    const start = page.indexOf('Subdomain Resolution Map')
    const map = page.slice(start, page.indexOf('</table>', start))
    expect(map).toContain('shared edge')
    expect(map).not.toMatch(/unknown/i)
  })
})
