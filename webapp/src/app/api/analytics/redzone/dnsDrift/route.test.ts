/**
 * Red-zone DNS drift: names recorded on IP-mode target IPs are not drift (D-18).
 *
 * An IP-mode run records every hostname it sees on a target address as an
 * ExternalDomain under the mock root (`ip_hostname_reason` set). Read as
 * "foreign domains seen redirecting", each would be a false drift row. The
 * ExternalDomain arm keeps a node when it carries no hostname evidence (every
 * domain-mode ExternalDomain) or when it has redirect evidence (a target IP
 * that redirected to the name, which the aggregator wrote on the same node).
 *
 * The predicate is read from the route's Cypher and evaluated here on sample
 * nodes, so a rewrite that changes what it keeps fails this test.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/dnsDrift/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runReturn: Array<Record<string, unknown>> = []

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      return { records: runReturn.map(row => ({ get: (k: string) => row[k] })) }
    },
    close: async () => { /* no-op */ },
  }),
}))

const route = await import('./route')

function request(projectId: string): any {
  return { nextUrl: new URL(`http://localhost:3000/api/analytics/redzone/dnsDrift?projectId=${projectId}`) }
}

beforeEach(() => {
  runCalls.length = 0
  runReturn = []
})

async function externalDomainArm(): Promise<{ pattern: string; predicate: string }> {
  await route.GET(request('p1'))
  const match = runCalls[0].cypher.match(
    /OPTIONAL MATCH (\(d\)-\[:HAS_EXTERNAL_DOMAIN\]->\(ext:ExternalDomain\))\s+WHERE (.+?)\n/)
  expect(match, 'the ExternalDomain arm has its own WHERE').not.toBeNull()
  return { pattern: match![1], predicate: match![2].trim() }
}

type Node = Record<string, unknown>

/** The predicate's two shapes, evaluated on a node; anything else throws. */
function keeps(predicate: string, ext: Node): boolean {
  return predicate.split(/\s+OR\s+/).some(term => {
    const isNull = term.match(/^ext\.(\w+) IS NULL$/)
    if (isNull) return ext[isNull[1]] == null
    const nonEmpty = term.match(/^size\(coalesce\(ext\.(\w+), \[\]\)\) > 0$/)
    if (nonEmpty) return ((ext[nonEmpty[1]] as unknown[] | undefined) ?? []).length > 0
    throw new Error(`unexpected term in the ExternalDomain filter: ${term}`)
  })
}

describe('dnsDrift: hostnames recorded on target IPs', () => {
  test('a name only recorded on a target IP is left out', async () => {
    const { predicate } = await externalDomainArm()
    expect(keeps(predicate, { domain: 'web.example.com', sources: ['ptr'],
      ip_hostname_reason: 'record_only' })).toBe(false)
  })

  test('a recorded name a target IP redirected to is kept', async () => {
    const { predicate } = await externalDomainArm()
    expect(keeps(predicate, { domain: 'moved.example.com', sources: ['http_probe_redirect', 'http_redirect'],
      ip_hostname_reason: 'record_only', redirect_from_urls: ['https://203.0.113.10/'] })).toBe(true)
  })

  test('a domain-mode ExternalDomain is kept as before', async () => {
    const { predicate } = await externalDomainArm()
    expect(keeps(predicate, { domain: 'foreign.example.net', sources: ['urlscan'] })).toBe(true)
    expect(keeps(predicate, { domain: 'idp.example.net', sources: ['http_probe_redirect'],
      redirect_from_urls: ['https://www.example.com/login'] })).toBe(true)
  })

  test('the filter narrows the ExternalDomain arm only, never the Domain row', async () => {
    const { pattern } = await externalDomainArm()
    expect(pattern).toBe('(d)-[:HAS_EXTERNAL_DOMAIN]->(ext:ExternalDomain)')
    const cypher = runCalls[0].cypher
    expect(cypher).toMatch(/MATCH \(d:Domain \{project_id: \$pid\}\)/)
    expect(cypher).toMatch(/WHERE size\(historicResolutionsClean\) > 0\s+OR size\(externalDomainsClean\) > 0/s)
    expect(runCalls[0].params).toEqual({ pid: 'p1' })
  })

  test('a kept row is returned unchanged', async () => {
    runReturn = [{
      nodeId: '7', domain: 'example.com', historicResolutions: [], historicIpCount: 0,
      currentIps: [], currentAsns: [], currentCountries: [],
      externalDomains: [{ domain: 'moved.example.com', sources: ['http_probe_redirect'], timesSeen: { low: 2 },
        countriesSeen: [], firstSeenAt: null, redirectFromUrls: ['https://203.0.113.10/'] }],
      externalDomainCount: { low: 1 }, danglingSubs: [], danglingSubCount: 0,
    }]
    const body = await (await route.GET(request('p1'))).json()
    expect(body.rows[0].externalDomains).toEqual([{ domain: 'moved.example.com',
      sources: ['http_probe_redirect'], timesSeen: 2, countriesSeen: [], firstSeenAt: null,
      redirectFromUrls: ['https://203.0.113.10/'] }])
    expect(body.rows[0].externalDomainCount).toBe(1)
  })
})
