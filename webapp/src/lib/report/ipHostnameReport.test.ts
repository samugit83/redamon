/** @vitest-environment node */
/**
 * The report's IP Target Map under "Hostnames on target IPs" (design §6.4).
 *
 * Per IP the map lists only the names the hostname selection scanned there and
 * that the project's CURRENT policy still admits (a narrowing leaves `scanned`
 * on the node until the next full run), never a dashed placeholder label; the
 * names only recorded on the IP are a count plus the first five; and the empty
 * cell says what the mode did instead of "No reverse DNS". The Target
 * Information table names the mode with the recorded and scanned totals.
 *
 * Run: npx vitest run src/lib/report/ipHostnameReport.test.ts
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: async () => ({ records: [] }), close: async () => {} }),
}))

const { queryGraphOverview, admittedByCurrentPolicy } = await import('./reportData')
const { renderScope } = await import('./reportTemplate')
type ReportData = import('./reportData').ReportData
type HostnamePolicyRow = import('./reportData').HostnamePolicyRow

function int(n: number) { return { low: n, high: 0 } }
function rec(values: Record<string, unknown>) { return { get: (k: string) => values[k] } }

const RECORDED = ['a.example.org', 'b.example.org', 'c.example.org', 'd.example.org', 'e.example.org']

let ipRows: ReturnType<typeof rec>[] = []
let recordedTotal = 0
const queries: string[] = []
const session = {
  run: async (cypher: string) => {
    queries.push(cypher)
    if (cypher.includes('collect(DISTINCT s.name) AS hostnames')) return { records: ipRows }
    if (cypher.includes('AS recordedHostnames')) return { records: [rec({ recordedHostnames: int(recordedTotal) })] }
    return { records: [] }
  },
}

beforeEach(() => {
  queries.length = 0
  recordedTotal = 7
  ipRows = [
    rec({ ip: '203.0.113.10', version: 'ipv4', isCdn: false, cdnName: null, asn: null, ownership: 'dedicated',
          hostnames: ['app.example.com', 'shop.example.de', '203-0-113-10', null], openPorts: int(2),
          recordedCount: int(7), recordedSample: RECORDED }),
    rec({ ip: '203.0.113.11', version: 'ipv4', isCdn: false, cdnName: null, asn: null, ownership: null,
          hostnames: ['app.example.com'], openPorts: int(1), recordedCount: int(0), recordedSample: [] }),
  ]
})

const policy = (over: Partial<HostnamePolicyRow> = {}): HostnamePolicyRow => ({
  ipMode: true, ipHostnameMode: 'ip_only', ipHostnameInclude: [], ipHostnameExclude: [], ...over,
})

describe('the data: which names are an IP\'s hostnames', () => {
  test('the IP query reads selection-scanned Subdomains and SEEN_ON names, keyed on the project', async () => {
    await queryGraphOverview(session, 'p1', policy())
    const q = queries.find(c => c.includes('collect(DISTINCT s.name) AS hostnames'))!
    expect(q).toContain("(s:Subdomain {project_id: $pid, source: 'ip_hostname_selection'})")
    expect(q).toContain("s.ip_hostname_reason = 'scanned'")
    // The selection stamps its source on the RESOLVES_TO it pins.
    expect(q).toContain("dnsr.source IS NULL OR dnsr.source = 'ip_hostname_selection'")
    expect(q).toContain('(ed:ExternalDomain {project_id: $pid})-[:SEEN_ON]->(ip)')
    expect(q).toContain('collect(DISTINCT ed.domain)[0..5] AS recordedSample')
    const total = queries.find(c => c.includes('AS recordedHostnames'))!
    expect(total).toContain('(ed:ExternalDomain {project_id: $pid})-[:SEEN_ON]->(:IP {project_id: $pid})')
    expect(total).toContain('count(DISTINCT ed)')
  })

  test.each([
    ['ip_only', {}, [[], []]],
    ['record_only', {}, [[], []]],
    ['record_filter', { ipHostnameInclude: ['*.example.com'] }, [['app.example.com'], ['app.example.com']]],
    ['scan_all', { ipHostnameScanAllConfirmed: true }, [['app.example.com', 'shop.example.de'], ['app.example.com']]],
  ] as const)('%s: only the names its current policy admits, never a placeholder', async (mode, over, expected) => {
    const overview = await queryGraphOverview(session, 'p1', policy({ ipHostnameMode: mode, ...over }))
    expect(overview.ipMappings.map(m => m.hostnames)).toEqual(expected)
  })

  test('a scanned name the policy no longer admits is dropped (narrowed after the run)', async () => {
    const overview = await queryGraphOverview(session, 'p1', policy({
      ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com', '*.example.de'],
      ipHostnameExclude: ['shop.example.de'],
    }))
    expect(overview.ipMappings[0].hostnames).toEqual(['app.example.com'])
  })

  test('without a readable policy no name counts as scanned (fail closed)', async () => {
    expect((await queryGraphOverview(session, 'p1')).ipMappings[0].hostnames).toEqual([])
    const unreadable = policy({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com', '*.com'] })
    expect((await queryGraphOverview(session, 'p1', unreadable)).ipMappings[0].hostnames).toEqual([])
    const notIp = policy({ ipMode: false, ipHostnameMode: 'scan_all' })
    expect((await queryGraphOverview(session, 'p1', notIp)).ipMappings[0].hostnames).toEqual([])
  })

  test('the recorded names: a count and the first five, per IP', async () => {
    const overview = await queryGraphOverview(session, 'p1', policy({ ipHostnameMode: 'record_only' }))
    expect(overview.ipMappings.map(m => [m.recordedCount, m.recordedSample])).toEqual([[7, RECORDED], [0, []]])
  })

  test('the totals are distinct across IPs', async () => {
    recordedTotal = 9
    const overview = await queryGraphOverview(session, 'p1', policy({ ipHostnameMode: 'scan_all' }))
    // app.example.com is on both IPs: one scanned name.
    expect(overview.ipHostnames).toEqual({ recorded: 9, scanned: 2 })
  })

  test('a row from an older graph without the recorded columns reads as none recorded', async () => {
    ipRows = [rec({ ip: '203.0.113.12', version: 'ipv4', isCdn: false, cdnName: null, asn: null,
                    ownership: null, hostnames: [], openPorts: int(0) })]
    const overview = await queryGraphOverview(session, 'p1', policy())
    expect(overview.ipMappings[0]).toMatchObject({ recordedCount: 0, recordedSample: [], hostnames: [] })
  })

  test('admittedByCurrentPolicy is the §6.3 filter on its own', () => {
    const names = ['app.example.com', 'old.example.com', 'x.other.test']
    const filter = policy({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'],
                            ipHostnameExclude: ['old.example.com'] })
    expect(admittedByCurrentPolicy(names, filter)).toEqual(['app.example.com'])
    expect(admittedByCurrentPolicy(names, policy({ ipHostnameMode: 'scan_all' }))).toEqual(names)
    expect(admittedByCurrentPolicy(names, policy({ ipHostnameMode: 'unknown' }))).toEqual([])
    expect(admittedByCurrentPolicy(names, null)).toEqual([])
  })
})

describe('the rendered IP Target Map', () => {
  async function page(row: HostnamePolicyRow, ipMode = true) {
    const overview = await queryGraphOverview(session, 'p1', row)
    const data = {
      project: { ...row, ipMode, targetIps: ipMode ? ['203.0.113.10', '203.0.113.11'] : [],
                 targetDomain: 'example.com', stealthMode: false },
      graphOverview: {
        totalNodes: 0, suppressedRules: [], judged: { personFalsePositive: 0, resolved: 0, aiFlagged: 0 },
        subdomainStats: { total: 0, resolved: 0, uniqueIps: 2 },
        infrastructureStats: { totalIps: 2 },
        endpointCoverage: { baseUrls: 0, endpoints: 0, parameters: 0 },
        ipMappings: overview.ipMappings,
        subdomainMappings: overview.subdomainMappings,
        ipHostnames: overview.ipHostnames,
      },
    } as unknown as ReportData
    return renderScope(data)
  }
  const mapRows = (html: string) => {
    const start = html.indexOf('IP Target Map')
    return html.slice(start, html.indexOf('</table>', start)).split('<tr>').slice(2)
  }

  test('ip_only: the empty cell and the mode line say no hostname is looked up', async () => {
    const html = await page(policy())
    expect(html).toContain('<th>Scanned hostnames</th><th>Recorded hostnames</th>')
    expect(mapRows(html)[0]).toContain('IP only: hostnames not looked up')
    expect(html).toContain('<tr><td>Hostnames on target IPs</td><td>IP only (hostnames not looked up)</td></tr>')
    expect(html).not.toContain('No reverse DNS')
  })

  test('record_only: nothing scanned, the recorded count and the first five names', async () => {
    const html = await page(policy({ ipHostnameMode: 'record_only' }))
    const [first, second] = mapRows(html)
    expect(first).toContain('None scanned')
    expect(first).toContain(`7: ${RECORDED.join(', ')} and 2 more`)
    expect(second).toContain('No hostname found')
    expect(html).toContain('<td>Record hostnames · 7 recorded, 0 scanned</td>')
  })

  test('record_filter: the admitted names are listed, the placeholder never', async () => {
    const html = await page(policy({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }))
    expect(mapRows(html)[0]).toContain('app.example.com')
    expect(mapRows(html)[0]).not.toContain('shop.example.de')
    expect(html).not.toContain('203-0-113-10')
    expect(html).toContain('<td>Record + scan matching · 7 recorded, 1 scanned</td>')
  })

  test('scan_all: every scanned name, still no placeholder', async () => {
    const html = await page(policy({ ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }))
    expect(mapRows(html)[0]).toContain('app.example.com<br/>shop.example.de')
    expect(html).not.toContain('203-0-113-10')
    expect(html).toContain('<td>Record + scan all · 7 recorded, 2 scanned</td>')
  })

  test('a recorded name is HTML-escaped', async () => {
    ipRows = [rec({ ip: '203.0.113.10', version: 'ipv4', isCdn: false, cdnName: null, asn: null, ownership: null,
                    hostnames: [], openPorts: int(0), recordedCount: int(1), recordedSample: ['<b>x.example.org'] })]
    const html = await page(policy({ ipHostnameMode: 'record_only' }))
    expect(html).toContain('&lt;b&gt;x.example.org')
    expect(html).not.toContain('<b>x.example.org')
  })

  test('a domain project shows no hostname-mode row', async () => {
    const html = await page(policy(), false)
    expect(html).not.toContain('Hostnames on target IPs')
  })
})
