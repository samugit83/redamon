/**
 * Route handler tests for Phase B endpoints: webInitAccess, paramMatrix,
 * sharedInfra, dnsEmail.
 *
 * Strategy mirrors redzoneRoutes.test.ts: mock getSession → deterministic stub,
 * capture Cypher text + params, return canned records, assert JSON shape.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/phaseBRoutes.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runReturn: Array<Record<string, unknown>> | Array<Array<Record<string, unknown>>> = []
let shouldThrow: Error | null = null

vi.mock('@/app/api/graph/neo4j', () => {
  let callIdx = 0
  return {
    getSession: () => ({
      run: async (cypher: string, params: Record<string, unknown>) => {
        runCalls.push({ cypher, params })
        if (shouldThrow) throw shouldThrow
        // If runReturn is nested arrays, serve per-call; else the same each call.
        const isNested = Array.isArray(runReturn) && runReturn.length > 0 && Array.isArray(runReturn[0])
        const dataset = (isNested ? (runReturn[callIdx] as Array<Record<string, unknown>>) : runReturn as Array<Record<string, unknown>>) || []
        callIdx++
        return { records: dataset.map(row => ({ get: (k: string) => row[k] })) }
      },
      close: async () => { /* no-op */ },
    }),
  }
})

const webInitRoute     = await import('./webInitAccess/route')
const paramMatrixRoute = await import('./paramMatrix/route')
const sharedInfraRoute = await import('./sharedInfra/route')
const dnsEmailRoute    = await import('./dnsEmail/route')

function makeRequest(projectId: string | null): any {
  const url = projectId
    ? `http://localhost:3000/api/analytics/redzone/test?projectId=${projectId}`
    : 'http://localhost:3000/api/analytics/redzone/test'
  return { nextUrl: new URL(url) }
}

beforeEach(async () => {
  runCalls.length = 0
  runReturn = []
  shouldThrow = null
  // Reset mocked callIdx by reimporting (cheap in vitest)
  vi.resetModules()
})

// ---------------------------------------------------------------------------
// Shared: contract tests across all 4 routes
// ---------------------------------------------------------------------------
describe('phase B: shared contract', () => {
  test.each([
    ['webInitAccess', webInitRoute.GET],
    ['paramMatrix',   paramMatrixRoute.GET],
    ['sharedInfra',   sharedInfraRoute.GET],
    ['dnsEmail',      dnsEmailRoute.GET],
  ])('%s returns 400 when projectId is missing', async (_, handler) => {
    const res = await handler(makeRequest(null))
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toMatch(/projectId/i)
  })

  test.each([
    ['webInitAccess', webInitRoute.GET],
    ['paramMatrix',   paramMatrixRoute.GET],
    ['sharedInfra',   sharedInfraRoute.GET],
    ['dnsEmail',      dnsEmailRoute.GET],
  ])('%s returns 500 on Neo4j failure', async (_, handler) => {
    shouldThrow = new Error('connection refused')
    const res = await handler(makeRequest('p1'))
    expect(res.status).toBe(500)
  })

  test.each([
    ['webInitAccess', webInitRoute.GET],
    ['paramMatrix',   paramMatrixRoute.GET],
    ['dnsEmail',      dnsEmailRoute.GET],
  ])('%s passes projectId as $pid', async (_, handler) => {
    await handler(makeRequest('p-project'))
    expect(runCalls.length).toBeGreaterThan(0)
    expect(runCalls.some(c => c.params.pid === 'p-project')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// webInitAccess
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/webInitAccess', () => {
  test('Cypher filters auth endpoints by category AND login-path regex', async () => {
    runReturn = []
    await webInitRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/ep\.category IN \$authCategories/)
    expect(c).toMatch(/login\|signin\|sign-in\|admin\|auth/)
  })

  test('Cypher filter joins HAS_HEADER where is_security_header=true', async () => {
    await webInitRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/HAS_HEADER.*is_security_header = true/s)
  })

  test('passes the merged WEB_AUTH + HEADER_HYGIENE type list as $allTypes', async () => {
    await webInitRoute.GET(makeRequest('p1'))
    const types = runCalls[0].params.allTypes as string[]
    expect(types).toEqual(expect.arrayContaining([
      'login_no_https', 'basic_auth_no_tls', 'session_no_secure', 'session_no_httponly',
      'cache_control_missing', 'csp_unsafe_inline', 'insecure_form_action', 'no_rate_limiting',
      'missing_referrer_policy', 'missing_permissions_policy', 'missing_coop', 'missing_corp', 'missing_coep',
    ]))
  })

  test('builds headerGrid from securityHeadersPresent (case-insensitive)', async () => {
    runReturn = [{
      baseUrl: 'https://api.example.com',
      scheme: 'https',
      statusCode: 200,
      server: 'nginx',
      subdomain: 'api.example.com',
      authEndpointPaths: ['/login'],
      authEndpointMethods: ['POST'],
      authCategories: ['auth'],
      authEndpointCount: { low: 1, high: 0 },
      totalEndpointCount: { low: 8, high: 0 },
      vulnTags: ['login_no_https'],
      securityHeadersPresent: ['content-security-policy', 'X-Frame-Options'],
    }]
    const res = await webInitRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(1)
    const r = body.rows[0]
    expect(r.headerGrid['Content-Security-Policy']).toBe(true)
    expect(r.headerGrid['X-Frame-Options']).toBe(true)
    expect(r.headerGrid['Strict-Transport-Security']).toBe(false)
    // 4 headers missing + 1 vuln = 5 → D
    expect(r.grade).toBe('D')
  })
})

// ---------------------------------------------------------------------------
// paramMatrix
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/paramMatrix', () => {
  test('Cypher matches Parameter and conditionally joins AFFECTS_PARAMETER', async () => {
    await paramMatrixRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/MATCH \(p:Parameter \{project_id: \$pid\}\)/)
    expect(c).toMatch(/AFFECTS_PARAMETER/)
    expect(c).toMatch(/is_injectable = true OR size\(vulns\) > 0/)
  })

  test('orders by severity then injectable flag', async () => {
    await paramMatrixRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/CASE v\.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1/)
    expect(c).toMatch(/p\.is_injectable DESC/)
  })

  test('maps Neo4j record into ParamRow shape + meta counts', async () => {
    runReturn = [
      { paramName: 'q', position: 'query', endpointPath: '/search', paramBaseUrl: 'https://a', sampleValue: '<script>', isInjectable: true, paramType: 'string', paramCategory: 'user_input', endpointMethod: 'GET', endpointFullUrl: 'https://a/search', endpointCategory: 'search', baseUrl: 'https://a', subdomain: 'a.com', vulnId: 'v1', templateId: 'xss-reflected', vulnName: 'Reflected XSS', vulnSeverity: 'high', vulnSource: 'nuclei', matcherName: 'word', extractorName: null, fuzzingMethod: 'GET', fuzzingPosition: 'query', matchedAt: 'https://a/search?q=...', cvssScore: 7.5 },
      { paramName: 'id', position: 'query', endpointPath: '/item', paramBaseUrl: 'https://a', sampleValue: '1', isInjectable: true, paramType: 'int', paramCategory: null, endpointMethod: 'GET', endpointFullUrl: 'https://a/item?id=1', endpointCategory: null, baseUrl: 'https://a', subdomain: 'a.com', vulnId: null, templateId: null, vulnName: null, vulnSeverity: null, vulnSource: null, matcherName: null, extractorName: null, fuzzingMethod: null, fuzzingPosition: null, matchedAt: null, cvssScore: null },
    ]
    const res = await paramMatrixRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(2)
    expect(body.meta.injectableCount).toBe(2)
    expect(body.meta.withVulnCount).toBe(1)
    expect(body.rows[0].vulnSeverity).toBe('high')
    expect(body.rows[0].cvssScore).toBe(7.5)
    expect(body.rows[1].vulnId).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// sharedInfra
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/sharedInfra', () => {
  test('runs 3 Cypher queries: Certificate, IP-ASN, IP-shared', async () => {
    runReturn = []
    await sharedInfraRoute.GET(makeRequest('p1'))
    expect(runCalls).toHaveLength(3)
    expect(runCalls[0].cypher).toMatch(/MATCH \(cert:Certificate \{project_id: \$pid\}\)/)
    expect(runCalls[1].cypher).toMatch(/MATCH \(ip:IP \{project_id: \$pid\}\)/)
    expect(runCalls[1].cypher).toMatch(/WHERE ip\.asn IS NOT NULL/)
    expect(runCalls[2].cypher).toMatch(/MATCH \(ip:IP \{project_id: \$pid\}\)/)
  })

  test('each cluster query enforces hostCount >= 2', async () => {
    await sharedInfraRoute.GET(makeRequest('p1'))
    for (const call of runCalls) {
      expect(call.cypher).toMatch(/WHERE size\([a-zA-Z]+\) >= 2/)
    }
  })

  test('union results sorted by hostCount DESC', async () => {
    runReturn = [
      // Call 0: cert clusters
      [
        { clusterType: 'certificate', clusterKey: '*.example.com', certCn: '*.example.com', certIssuer: "Let's Encrypt", certNotAfter: '2026-07-01T00:00:00Z', tlsVersion: 'TLS 1.3', cipher: 'AES', hostCount: { low: 3, high: 0 }, hosts: ['a', 'b', 'c'], baseurls: ['https://a'], asn: null, country: null, ipAddress: null },
      ],
      // Call 1: asn clusters
      [
        { clusterType: 'asn', clusterKey: 'AS13335', certCn: null, certIssuer: null, certNotAfter: null, tlsVersion: null, cipher: null, hostCount: { low: 5, high: 0 }, hosts: ['x', 'y', 'z'], baseurls: [], asn: 'AS13335', country: 'US', ipAddress: null },
      ],
      // Call 2: ip clusters
      [
        { clusterType: 'ip', clusterKey: '1.2.3.4', certCn: null, certIssuer: null, certNotAfter: null, tlsVersion: null, cipher: null, hostCount: { low: 2, high: 0 }, hosts: ['a', 'b'], baseurls: [], asn: 'AS99', country: 'US', ipAddress: '1.2.3.4' },
      ],
    ]
    // Vitest has already frozen the mock; use doMock with nested per-call return:
    let idx = 0
    const fixtures = runReturn as Array<Array<Record<string, unknown>>>
    vi.doMock('@/app/api/graph/neo4j', () => ({
      getSession: () => ({
        run: async () => {
          const ds = fixtures[idx++] || []
          return { records: ds.map(row => ({ get: (k: string) => row[k] })) }
        },
        close: async () => {},
      }),
    }))
    const mod = await import('./sharedInfra/route')
    const res = await mod.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(3)
    // Sorted by hostCount DESC: asn (5) → cert (3) → ip (2)
    expect(body.rows[0].clusterType).toBe('asn')
    expect(body.rows[1].clusterType).toBe('certificate')
    expect(body.rows[2].clusterType).toBe('ip')
    expect(body.meta.certClusters).toBe(1)
    expect(body.meta.asnClusters).toBe(1)
    expect(body.meta.ipClusters).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// dnsEmail
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/dnsEmail', () => {
  test('Cypher walks Domain → apex Subdomain → DNSRecord', async () => {
    await dnsEmailRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/MATCH \(d:Domain \{project_id: \$pid\}\)/)
    expect(c).toMatch(/HAS_SUBDOMAIN.*apex:Subdomain \{name: d\.name\}/s)
    expect(c).toMatch(/HAS_DNS_RECORD.*dns:DNSRecord/s)
  })

  test('filters DNS-layer vulns by exact type string', async () => {
    await dnsEmailRoute.GET(makeRequest('p1'))
    const params = runCalls[0].params
    expect(params.dnsTypes).toEqual(expect.arrayContaining([
      'spf_missing', 'dmarc_missing', 'dnssec_missing', 'zone_transfer',
    ]))
  })

  test('derives SPF/DMARC presence + DNSSEC + vuln-tag signals', async () => {
    runReturn = [{
      domain: 'example.com',
      dnssec: 'signedDelegation',
      domainNameServers: ['ns1.example.com', 'ns2.example.com'],
      whoisEmails: ['abuse@example.com'],
      registrar: 'Gandi SAS',
      organization: 'Example Inc',
      country: 'US',
      creationDate: null,
      expirationDate: '2030-01-01T00:00:00Z',
      registrarStatus: ['clientTransferProhibited'],
      vtMaliciousCount: { low: 0, high: 0 },
      vtReputation: { low: 5, high: 0 },
      otxPulseCount: { low: 0, high: 0 },
      mxRecords: ['mx1.example.com.', 'mx2.example.com.'],
      nsRecords: ['ns1.example.com.', 'ns2.example.com.'],
      txtRecords: [
        'v=spf1 include:_spf.google.com -all',
        'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
      ],
      soaRecords: [],
      vulnTags: [],
    }]
    const res = await dnsEmailRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(1)
    const r = body.rows[0]
    expect(r.domain).toBe('example.com')
    expect(r.spfPresent).toBe(true)
    expect(r.spfStrict).toBe(true)   // -all
    expect(r.dmarcPresent).toBe(true)
    expect(r.dmarcPolicy).toBe('reject')
    expect(r.dnssecEnabled).toBe(true)
    expect(r.dnssecMissing).toBe(false)
    expect(r.spfMissing).toBe(false)
    expect(r.dmarcMissing).toBe(false)
    expect(r.zoneTransferOpen).toBe(false)
    expect(r.mxCount).toBe(2)
    expect(r.nameServerCount).toBe(2)
  })

  test('marks missing signals when vuln tags present even if TXT absent', async () => {
    runReturn = [{
      domain: 'naked.example.com',
      dnssec: 'unsigned',
      domainNameServers: [],
      whoisEmails: [],
      registrar: null,
      organization: null,
      country: null,
      expirationDate: null,
      registrarStatus: [],
      vtMaliciousCount: null,
      vtReputation: null,
      otxPulseCount: null,
      mxRecords: [],
      nsRecords: [],
      txtRecords: [],
      soaRecords: [],
      vulnTags: ['spf_missing', 'dmarc_missing', 'dnssec_missing', 'zone_transfer'],
    }]
    const res = await dnsEmailRoute.GET(makeRequest('p1'))
    const body = await res.json()
    const r = body.rows[0]
    expect(r.spfMissing).toBe(true)
    expect(r.dmarcMissing).toBe(true)
    expect(r.dnssecMissing).toBe(true)
    expect(r.dnssecEnabled).toBe(false)
    expect(r.zoneTransferOpen).toBe(true)
  })
})
