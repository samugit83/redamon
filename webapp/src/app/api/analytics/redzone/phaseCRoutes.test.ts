/**
 * Route handler tests for Phase C endpoints: threatIntel, supplyChain, dnsDrift.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/phaseCRoutes.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runReturn: Array<Record<string, unknown>> = []
let runReturnByCall: Array<Array<Record<string, unknown>>> | null = null
let shouldThrow: Error | null = null

vi.mock('@/app/api/graph/neo4j', () => ({
  getSession: () => {
    let callIdx = 0
    return {
      run: async (cypher: string, params: Record<string, unknown>) => {
        runCalls.push({ cypher, params })
        if (shouldThrow) throw shouldThrow
        const dataset = runReturnByCall
          ? (runReturnByCall[callIdx++] || [])
          : runReturn
        return { records: dataset.map(row => ({ get: (k: string) => row[k] })) }
      },
      close: async () => { /* no-op */ },
    }
  },
}))

const threatIntelRoute = await import('./threatIntel/route')
const supplyChainRoute = await import('./supplyChain/route')
const dnsDriftRoute    = await import('./dnsDrift/route')

function makeRequest(projectId: string | null): any {
  const url = projectId
    ? `http://localhost:3000/api/analytics/redzone/test?projectId=${projectId}`
    : 'http://localhost:3000/api/analytics/redzone/test'
  return { nextUrl: new URL(url) }
}

beforeEach(() => {
  runCalls.length = 0
  runReturn = []
  runReturnByCall = null
  shouldThrow = null
})

// ---------------------------------------------------------------------------
// Shared contract
// ---------------------------------------------------------------------------
describe('phase C: shared contract', () => {
  test.each([
    ['threatIntel', threatIntelRoute.GET],
    ['supplyChain', supplyChainRoute.GET],
    ['dnsDrift',    dnsDriftRoute.GET],
  ])('%s returns 400 when projectId is missing', async (_, handler) => {
    const res = await handler(makeRequest(null))
    expect(res.status).toBe(400)
  })

  test.each([
    ['threatIntel', threatIntelRoute.GET],
    ['supplyChain', supplyChainRoute.GET],
    ['dnsDrift',    dnsDriftRoute.GET],
  ])('%s returns 500 on Neo4j failure', async (_, handler) => {
    shouldThrow = new Error('neo4j down')
    const res = await handler(makeRequest('p1'))
    expect(res.status).toBe(500)
  })

  test.each([
    ['threatIntel', threatIntelRoute.GET],
    ['supplyChain', supplyChainRoute.GET],
    ['dnsDrift',    dnsDriftRoute.GET],
  ])('%s passes projectId as $pid', async (_, handler) => {
    await handler(makeRequest('my-proj'))
    expect(runCalls.some(c => c.params.pid === 'my-proj')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// threatIntel
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/threatIntel', () => {
  test('runs 2 Cypher queries (Domain-side + IP-side)', async () => {
    await threatIntelRoute.GET(makeRequest('p1'))
    expect(runCalls).toHaveLength(2)
    expect(runCalls[0].cypher).toMatch(/MATCH \(d:Domain \{project_id: \$pid\}\)/)
    expect(runCalls[1].cypher).toMatch(/MATCH \(ip:IP \{project_id: \$pid\}\)/)
  })

  test('both queries traverse APPEARS_IN_PULSE + ASSOCIATED_WITH_MALWARE', async () => {
    await threatIntelRoute.GET(makeRequest('p1'))
    for (const call of runCalls) {
      expect(call.cypher).toMatch(/APPEARS_IN_PULSE.*ThreatPulse/s)
      expect(call.cypher).toMatch(/ASSOCIATED_WITH_MALWARE.*Malware/s)
    }
  })

  test('Domain query filters on any threat signal (VT / OTX / CriminalIP / pulse)', async () => {
    await threatIntelRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/d\.vt_malicious_count > 0/)
    expect(c).toMatch(/d\.otx_pulse_count > 0/)
    expect(c).toMatch(/d\.criminalip_abuse_count > 0/)
    expect(c).toMatch(/pulseCount > 0/)
    expect(c).toMatch(/malwareCount > 0/)
  })

  test('IP query additionally surfaces tor/proxy/vpn/darkweb flags', async () => {
    await threatIntelRoute.GET(makeRequest('p1'))
    const c = runCalls[1].cypher
    expect(c).toMatch(/ip\.criminalip_is_tor = true/)
    expect(c).toMatch(/ip\.criminalip_is_proxy = true/)
    expect(c).toMatch(/ip\.criminalip_is_vpn = true/)
    expect(c).toMatch(/ip\.criminalip_is_darkweb = true/)
  })

  test('rows are merged and sorted by pulseCount DESC, vtMaliciousCount DESC', async () => {
    runReturnByCall = [
      [
        // domain query
        { assetType: 'Domain', asset: 'lowvt.com', vtMaliciousCount: { low: 1, high: 0 }, vtSuspiciousCount: null, vtReputation: null, vtTags: [], vtLastAnalysisDate: null, vtJarm: null, otxPulseCount: { low: 0, high: 0 }, otxUrlCount: null, otxAdversaries: [], otxMalwareFamilies: [], otxTlp: null, otxAttackIds: [], criminalipRiskGrade: null, criminalipAbuseCount: null, criminalipCurrentService: null, pulseNames: [], pulseAdversaries: [], pulseCount: { low: 0, high: 0 }, malwareHashes: [], malwareCount: { low: 0, high: 0 } },
        { assetType: 'Domain', asset: 'highpulse.com', vtMaliciousCount: { low: 0, high: 0 }, vtSuspiciousCount: null, vtReputation: null, vtTags: [], vtLastAnalysisDate: null, vtJarm: null, otxPulseCount: { low: 5, high: 0 }, otxUrlCount: null, otxAdversaries: ['APT28'], otxMalwareFamilies: [], otxTlp: null, otxAttackIds: [], criminalipRiskGrade: null, criminalipAbuseCount: null, criminalipCurrentService: null, pulseNames: ['APT28 pulse'], pulseAdversaries: ['APT28'], pulseCount: { low: 5, high: 0 }, malwareHashes: [], malwareCount: { low: 0, high: 0 } },
      ],
      [
        // ip query
        { assetType: 'IP', asset: '1.2.3.4', vtMaliciousCount: { low: 10, high: 0 }, vtSuspiciousCount: null, vtReputation: null, vtTags: [], vtLastAnalysisDate: null, vtJarm: null, otxPulseCount: { low: 0, high: 0 }, otxUrlCount: null, otxAdversaries: [], otxMalwareFamilies: [], otxTlp: null, otxAttackIds: [], criminalipScoreInbound: null, criminalipIsTor: null, criminalipIsProxy: null, criminalipIsVpn: null, criminalipIsDarkweb: null, criminalipIsHosting: null, criminalipIsScanner: null, criminalipCountry: null, subdomains: [], pulseNames: [], pulseAdversaries: [], pulseCount: { low: 0, high: 0 }, malwareHashes: [], malwareCount: { low: 0, high: 0 } },
      ],
    ]
    const res = await threatIntelRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(3)
    // highpulse.com wins on pulseCount=5
    expect(body.rows[0].asset).toBe('highpulse.com')
    // IP with 10 vtMalicious next (pulseCount=0 ties, vtMalicious breaks tie)
    expect(body.rows[1].asset).toBe('1.2.3.4')
    // lowvt.com last (1 vtMalicious)
    expect(body.rows[2].asset).toBe('lowvt.com')
    expect(body.meta.domainCount).toBe(2)
    expect(body.meta.ipCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// supplyChain
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/supplyChain', () => {
  test("filters JsReconFinding.finding_type to supply-chain whitelist", async () => {
    await supplyChainRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/MATCH \(j:JsReconFinding \{project_id: \$pid\}\)/)
    expect(c).toMatch(/WHERE j\.finding_type IN \$types/)
    const types = runCalls[0].params.types as string[]
    expect(types).toEqual(expect.arrayContaining([
      'dependency_confusion',
      'source_map_exposure',
      'source_map_reference',
      'dev_comment',
      'framework',
      'cloud_asset',
    ]))
  })

  test('traverses BaseURL -> js_file parent -> finding via HAS_JS_FINDING', async () => {
    await supplyChainRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/HAS_JS_FILE.*parent:JsReconFinding \{finding_type: 'js_file'\}.*HAS_JS_FINDING/s)
  })

  test('orders by severity then finding_type', async () => {
    await supplyChainRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/CASE j\.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1/)
  })

  test('maps all record fields + computes meta.byType', async () => {
    runReturn = [
      { id: 'jf-1', findingType: 'dependency_confusion', severity: 'high', confidence: 'high', title: 'npm package unclaimed', detail: null, evidence: 'internal-pkg-v1', sourceUrl: 'https://a/app.js', baseUrlProp: 'https://a', packageName: 'internal-pkg-v1', version: '1.0.0', cloudProvider: null, cloudAssetType: null, discoveredAt: '2026-04-01', baseUrl: 'https://a', subdomain: 'a.com', parentJsUrl: 'https://a/app.js' },
      { id: 'jf-2', findingType: 'source_map_exposure', severity: 'medium', confidence: 'high', title: 'map reachable', detail: null, evidence: null, sourceUrl: 'https://a/app.js.map', baseUrlProp: 'https://a', packageName: null, version: null, cloudProvider: null, cloudAssetType: null, discoveredAt: null, baseUrl: 'https://a', subdomain: 'a.com', parentJsUrl: 'https://a/app.js' },
      { id: 'jf-3', findingType: 'dependency_confusion', severity: 'low', confidence: 'medium', title: null, detail: null, evidence: null, sourceUrl: 'https://b/lib.js', baseUrlProp: 'https://b', packageName: 'other-pkg', version: null, cloudProvider: null, cloudAssetType: null, discoveredAt: null, baseUrl: 'https://b', subdomain: 'b.com', parentJsUrl: null },
    ]
    const res = await supplyChainRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(3)
    expect(body.meta.byType['dependency_confusion']).toBe(2)
    expect(body.meta.byType['source_map_exposure']).toBe(1)
    const r0 = body.rows[0]
    expect(r0.packageName).toBe('internal-pkg-v1')
    expect(r0.version).toBe('1.0.0')
    expect(r0.parentJsUrl).toBe('https://a/app.js')
  })
})

// ---------------------------------------------------------------------------
// dnsDrift
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/dnsDrift', () => {
  test('walks Domain with HISTORICALLY_RESOLVED_TO + HAS_EXTERNAL_DOMAIN', async () => {
    await dnsDriftRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/MATCH \(d:Domain \{project_id: \$pid\}\)/)
    expect(c).toMatch(/HISTORICALLY_RESOLVED_TO.*ipHist:IP/s)
    expect(c).toMatch(/HAS_EXTERNAL_DOMAIN.*ExternalDomain/s)
    expect(c).toMatch(/HAS_SUBDOMAIN.*Subdomain/s)
    expect(c).toMatch(/has_dns_records = false OR sd\.status = 'no_http'/)
  })

  test('preserves relationship edge properties first_seen / last_seen / record_type', async () => {
    await dnsDriftRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/firstSeen: rel\.first_seen/)
    expect(c).toMatch(/lastSeen: rel\.last_seen/)
    expect(c).toMatch(/recordType: rel\.record_type/)
  })

  test('derives ASN + country drift (historic minus current) + last resolution date', async () => {
    runReturn = [{
      domain: 'example.com',
      historicResolutions: [
        { address: '1.1.1.1', asn: 'AS111', country: 'US', firstSeen: '2024-01-01', lastSeen: '2024-06-01', recordType: 'A' },
        { address: '2.2.2.2', asn: 'AS222', country: 'DE', firstSeen: '2024-06-01', lastSeen: '2025-01-01', recordType: 'A' },
      ],
      historicIpCount: { low: 2, high: 0 },
      currentIps: ['3.3.3.3'],
      currentAsns: ['AS333'],
      currentCountries: ['US'],
      externalDomains: [{ domain: 'foreign.tld', sources: ['urlscan'], timesSeen: { low: 3, high: 0 }, countriesSeen: ['US'], firstSeenAt: '2025-01-01', redirectFromUrls: ['https://example.com/redir'] }],
      externalDomainCount: { low: 1, high: 0 },
      danglingSubs: ['old.example.com'],
      danglingSubCount: { low: 1, high: 0 },
    }]
    const res = await dnsDriftRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(1)
    const r = body.rows[0]
    // ASN drift: historic [AS111, AS222] minus current [AS333] → [AS111, AS222]
    expect(r.asnDrift).toEqual(expect.arrayContaining(['AS111', 'AS222']))
    // Country drift: historic [US, DE] minus current [US] → [DE]
    expect(r.countryDrift).toEqual(['DE'])
    // lastResolutionDate is max(lastSeen) = 2025-01-01
    expect(r.lastResolutionDate).toMatch(/^2025-01-01/)
    expect(r.externalDomainCount).toBe(1)
    expect(r.danglingSubCount).toBe(1)
  })

  test('filters out domains with no drift / external / dangling signal', async () => {
    await dnsDriftRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/WHERE size\(historicResolutionsClean\) > 0\s+OR size\(externalDomainsClean\) > 0\s+OR size\(danglingSubsClean\) > 0/s)
  })
})
