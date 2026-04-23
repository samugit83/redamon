/**
 * Route handler tests for all 6 Red Zone endpoints.
 *
 * Strategy: mock `getSession` to return a deterministic stub that:
 *   - captures the Cypher text + params so we can assert the query shape,
 *   - returns a list of fake records each supporting `.get(key)`.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/redzoneRoutes.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

// --- Mock neo4j module BEFORE importing route modules ---
const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runReturn: Array<Record<string, unknown>> = []
let shouldThrow: Error | null = null

vi.mock('@/app/api/graph/neo4j', () => ({
  getSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      if (shouldThrow) throw shouldThrow
      const records = runReturn.map(row => ({
        get: (key: string) => row[key],
      }))
      return { records }
    },
    close: async () => { /* no-op */ },
  }),
}))

// Dynamic imports AFTER mock is set up
const killChainRoute = await import('./killChain/route')
const blastRadiusRoute = await import('./blastRadius/route')
const takeoverRoute = await import('./takeover/route')
const secretsRoute = await import('./secrets/route')
const netInitAccessRoute = await import('./netInitAccess/route')
const graphqlRoute = await import('./graphql/route')

function makeRequest(projectId: string | null): any {
  const url = projectId
    ? `http://localhost:3000/api/analytics/redzone/test?projectId=${projectId}`
    : 'http://localhost:3000/api/analytics/redzone/test'
  return {
    nextUrl: new URL(url),
  }
}

beforeEach(() => {
  runCalls.length = 0
  runReturn = []
  shouldThrow = null
})

// ---------------------------------------------------------------------------
// Shared: all routes reject when projectId missing
// ---------------------------------------------------------------------------
describe('all red-zone routes', () => {
  test.each([
    ['killChain', killChainRoute.GET],
    ['blastRadius', blastRadiusRoute.GET],
    ['takeover', takeoverRoute.GET],
    ['secrets', secretsRoute.GET],
    ['netInitAccess', netInitAccessRoute.GET],
    ['graphql', graphqlRoute.GET],
  ])('%s returns 400 when projectId is missing', async (_, handler) => {
    const res = await handler(makeRequest(null))
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toMatch(/projectId/i)
  })

  test.each([
    ['killChain', killChainRoute.GET],
    ['blastRadius', blastRadiusRoute.GET],
    ['takeover', takeoverRoute.GET],
    ['secrets', secretsRoute.GET],
    ['netInitAccess', netInitAccessRoute.GET],
    ['graphql', graphqlRoute.GET],
  ])('%s returns 500 when Neo4j throws', async (_, handler) => {
    shouldThrow = new Error('connection refused')
    const res = await handler(makeRequest('p1'))
    expect(res.status).toBe(500)
  })

  test.each([
    ['killChain', killChainRoute.GET],
    ['blastRadius', blastRadiusRoute.GET],
    ['takeover', takeoverRoute.GET],
    ['netInitAccess', netInitAccessRoute.GET],
    ['graphql', graphqlRoute.GET],
  ])('%s passes projectId as $pid parameter', async (_, handler) => {
    await handler(makeRequest('my-project'))
    expect(runCalls.length).toBeGreaterThan(0)
    const hasPid = runCalls.some(c => c.params.pid === 'my-project')
    expect(hasPid).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// killChain: projectId filter + Cypher shape + row transformation
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/killChain', () => {
  test('Cypher filters Subdomain by project_id and walks full chain', async () => {
    runReturn = []
    await killChainRoute.GET(makeRequest('p1'))
    expect(runCalls).toHaveLength(1)
    const c = runCalls[0].cypher
    expect(c).toMatch(/MATCH \(s:Subdomain \{project_id: \$pid\}\)/)
    expect(c).toMatch(/-\[:RESOLVES_TO\]->\(ip:IP\)/)
    expect(c).toMatch(/-\[:HAS_PORT\]->\(p:Port\)/)
    expect(c).toMatch(/-\[:RUNS_SERVICE\]->\(svc:Service\)/)
    expect(c).toMatch(/-\[:USES_TECHNOLOGY\]->\(t:Technology\)/)
    expect(c).toMatch(/-\[:HAS_KNOWN_CVE\]->\(c:CVE\)/)
    expect(c).toMatch(/-\[:HAS_CWE\]->\(m:MitreData\)/)
    expect(c).toMatch(/-\[:HAS_CAPEC\]->\(cap:Capec\)/)
    expect(c).toMatch(/ExploitGvm.*EXPLOITED_CVE/s)
  })

  test('orders results by cisaKev DESC, cvss DESC', async () => {
    runReturn = []
    await killChainRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/ORDER BY cisaKev DESC, cvss DESC/)
  })

  test('maps record fields to KillChainRow shape', async () => {
    runReturn = [{
      subdomain: 'api.example.com',
      ipAddress: '1.2.3.4',
      port: { low: 443, high: 0 },
      protocol: 'tcp',
      serviceName: 'HTTPS',
      serviceProduct: 'nginx',
      serviceVersion: '1.18',
      techName: 'nginx',
      techVersion: '1.18',
      cveId: 'CVE-2023-9999',
      cvss: 9.8,
      cveSeverity: 'critical',
      cisaKev: true,
      cweId: 'CWE-79',
      cweName: 'XSS',
      capecId: 'CAPEC-63',
      capecName: 'Reflected XSS',
      capecSeverity: 'High',
    }]
    const res = await killChainRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(1)
    const r = body.rows[0]
    expect(r.subdomain).toBe('api.example.com')
    expect(r.port).toBe(443)
    expect(r.cveId).toBe('CVE-2023-9999')
    expect(r.cvss).toBe(9.8)
    expect(r.cisaKev).toBe(true)
    expect(r.cweId).toBe('CWE-79')
    expect(body.meta.kevCount).toBe(1)
    expect(body.meta.totalRows).toBe(1)
  })

  test('kevCount counts only rows flagged cisaKev=true', async () => {
    runReturn = [
      { subdomain: 'a', cisaKev: true,  cveSeverity: 'high', port: { low: 80, high: 0 }, cvss: 7 },
      { subdomain: 'b', cisaKev: false, cveSeverity: 'high', port: { low: 80, high: 0 }, cvss: 7 },
      { subdomain: 'c', cisaKev: true,  cveSeverity: 'high', port: { low: 80, high: 0 }, cvss: 7 },
    ]
    const res = await killChainRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.meta.kevCount).toBe(2)
    expect(body.meta.totalRows).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// blastRadius: per-Technology aggregation
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/blastRadius', () => {
  test('Cypher aggregates by Technology with cross-joins', async () => {
    runReturn = []
    await blastRadiusRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/MATCH \(t:Technology \{project_id: \$pid\}\)-\[:HAS_KNOWN_CVE\]->\(c:CVE\)/)
    expect(c).toMatch(/BaseURL.*USES_TECHNOLOGY/s)
    expect(c).toMatch(/Service.*USES_TECHNOLOGY/s)
    expect(c).toMatch(/Port.*HAS_TECHNOLOGY/s)
    expect(c).toMatch(/ExploitGvm.*EXPLOITED_CVE/s)
    expect(c).toMatch(/ORDER BY kevCount DESC, maxCvss DESC, cveCount DESC/)
  })

  test('maps aggregate record to BlastRadiusRow', async () => {
    runReturn = [{
      techName: 'nginx',
      techVersion: '1.18',
      cveCount: { low: 5, high: 0 },
      maxCvss: 9.8,
      kevCount: { low: 2, high: 0 },
      baseUrlCount: { low: 12, high: 0 },
      ipCount: { low: 3, high: 0 },
      severities: ['critical', 'high'],
      topCveIds: ['CVE-2023-1', 'CVE-2023-2', 'CVE-2023-3'],
    }]
    const res = await blastRadiusRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(1)
    const r = body.rows[0]
    expect(r.techName).toBe('nginx')
    expect(r.cveCount).toBe(5)
    expect(r.kevCount).toBe(2)
    expect(r.baseUrlCount).toBe(12)
    expect(r.ipCount).toBe(3)
    expect(r.severities).toEqual(['critical', 'high'])
    expect(r.topCveIds).toHaveLength(3)
  })

  test('null tech name defaults to "Unknown"', async () => {
    runReturn = [{ techName: null, techVersion: null, cveCount: { low: 1, high: 0 }, maxCvss: null, kevCount: { low: 0, high: 0 }, baseUrlCount: { low: 0, high: 0 }, ipCount: { low: 0, high: 0 }, severities: [], topCveIds: [] }]
    const res = await blastRadiusRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows[0].techName).toBe('Unknown')
  })
})

// ---------------------------------------------------------------------------
// takeover: source filter + summary
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/takeover', () => {
  test("Cypher filters Vulnerability by source='takeover_scan'", async () => {
    runReturn = []
    await takeoverRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/MATCH \(v:Vulnerability \{project_id: \$pid, source: 'takeover_scan'\}\)/)
  })

  test('orders by verdict then confidence DESC', async () => {
    await takeoverRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/CASE v\.verdict WHEN 'confirmed' THEN 0 WHEN 'likely' THEN 1 ELSE 2 END/)
    expect(c).toMatch(/v\.confidence DESC/)
  })

  test('meta summary counts verdict buckets', async () => {
    runReturn = [
      { id: 'a', hostname: 'a.com', parentType: 'Subdomain', verdict: 'confirmed', provider: 'github-pages', method: 'cname', confidence: { low: 85, high: 0 }, severity: 'high', sources: ['subjack'], confirmationCount: { low: 2, high: 0 } },
      { id: 'b', hostname: 'b.com', parentType: 'Subdomain', verdict: 'likely',    provider: 'heroku', method: 'cname', confidence: { low: 65, high: 0 }, severity: 'medium', sources: ['nuclei'], confirmationCount: { low: 1, high: 0 } },
      { id: 'c', hostname: 'c.com', parentType: 'Subdomain', verdict: 'manual_review', provider: 'unknown', method: 'stale_a', confidence: { low: 30, high: 0 }, severity: 'info', sources: ['baddns'], confirmationCount: { low: 1, high: 0 } },
      { id: 'd', hostname: 'd.com', parentType: 'Subdomain', verdict: 'confirmed', provider: 'aws-s3', method: 'cname', confidence: { low: 90, high: 0 }, severity: 'high', sources: ['subjack', 'nuclei'], confirmationCount: { low: 2, high: 0 } },
    ]
    const res = await takeoverRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.meta.totalRows).toBe(4)
    expect(body.meta.confirmed).toBe(2)
    expect(body.meta.likely).toBe(1)
    expect(body.meta.manualReview).toBe(1)
  })

  test('maps confidence Neo4j int to plain number', async () => {
    runReturn = [{ id: 'x', hostname: 'x', parentType: 'Subdomain', verdict: 'confirmed', provider: 'github-pages', method: 'cname', confidence: { low: 75, high: 0 }, severity: 'high', sources: [], confirmationCount: { low: 1, high: 0 } }]
    const res = await takeoverRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows[0].confidence).toBe(75)
    expect(body.rows[0].confirmationCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// secrets: single Cypher; Secret nodes attached via BaseURL OR JsReconFinding
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/secrets', () => {
  test('runs a single Cypher that traverses both HAS_SECRET paths', async () => {
    runReturn = []
    await secretsRoute.GET(makeRequest('p1'))
    expect(runCalls).toHaveLength(1)
    const c = runCalls[0].cypher
    expect(c).toMatch(/MATCH \(s:Secret \{project_id: \$pid\}\)/)
    expect(c).toMatch(/\(buDirect:BaseURL\)-\[:HAS_SECRET\]->\(s\)/)
    expect(c).toMatch(/JsReconFinding.*finding_type: 'js_file'/s)
    expect(c).toMatch(/-\[:HAS_SECRET\]->\(s\)/)
    expect(c).toMatch(/\(buJs:BaseURL\)-\[:HAS_JS_FILE\]->\(j\)/)
  })

  test('sorts validated > format_validated > unvalidated then by type priority', async () => {
    runReturn = [
      { id: 's1', secretType: 'API Key', valueSample: 'k1', matchedText: null, entropy: 3.1, confidence: 'medium', severity: 'medium', sourceModule: 'js_recon', sourceUrl: 'http://a/app.js', secretBaseUrl: null, keyType: 'auth', detectionMethod: 'regex', validationStatus: 'unvalidated', baseUrl: 'http://a', subdomain: 'a.com', jsFileUrl: 'http://a/app.js', origin: 'JsReconFinding' },
      { id: 's2', secretType: 'AWS Secret Key', valueSample: 'akia...', matchedText: null, entropy: 4.8, confidence: 'high', severity: 'critical', sourceModule: 'resource_enum', sourceUrl: 'http://a/config.json', secretBaseUrl: null, keyType: 'cloud', detectionMethod: 'regex', validationStatus: 'validated', baseUrl: 'http://a', subdomain: 'a.com', jsFileUrl: null, origin: 'Secret' },
      { id: 's3', secretType: 'GitHub Token Classic', valueSample: 'ghp_', matchedText: null, entropy: 4.2, confidence: 'high', severity: 'high', sourceModule: 'js_recon', sourceUrl: 'http://a/app.js', secretBaseUrl: null, keyType: 'auth', detectionMethod: 'regex', validationStatus: 'format_validated', baseUrl: 'http://a', subdomain: 'a.com', jsFileUrl: 'http://a/app.js', origin: 'JsReconFinding' },
    ]
    const res = await secretsRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(3)
    // validated first, format_validated next, unvalidated last
    expect(body.rows[0].id).toBe('s2')   // AWS Secret Key, validated
    expect(body.rows[1].id).toBe('s3')   // GitHub Token, format_validated
    expect(body.rows[2].id).toBe('s1')   // API Key, unvalidated
  })

  test('origin label reflects source traversal (BaseURL direct vs JsReconFinding)', async () => {
    runReturn = [
      { id: 's-direct', secretType: 'AWS Secret Key', origin: 'Secret', validationStatus: 'validated' },
      { id: 's-js', secretType: 'AWS Secret Key', origin: 'JsReconFinding', validationStatus: 'validated' },
    ]
    const res = await secretsRoute.GET(makeRequest('p1'))
    const body = await res.json()
    const direct = body.rows.find((r: any) => r.id === 's-direct')
    const js = body.rows.find((r: any) => r.id === 's-js')
    expect(direct.origin).toBe('Secret')
    expect(js.origin).toBe('JsReconFinding')
  })
})

// ---------------------------------------------------------------------------
// netInitAccess: sensitive port filter + vuln merge
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/netInitAccess', () => {
  test('passes sensitive port list to Cypher as $ports', async () => {
    runReturn = []
    await netInitAccessRoute.GET(makeRequest('p1'))
    expect(runCalls).toHaveLength(2)
    const portsParam = runCalls[0].params.ports
    expect(Array.isArray(portsParam)).toBe(true)
    expect(portsParam).toContain(22)     // ssh
    expect(portsParam).toContain(3306)   // mysql
    expect(portsParam).toContain(5432)   // postgres
    expect(portsParam).toContain(6379)   // redis
    expect(portsParam).toContain(10250)  // k8s kubelet
  })

  test('both Cypher calls receive the vuln-type whitelist', async () => {
    runReturn = []
    await netInitAccessRoute.GET(makeRequest('p1'))
    for (const call of runCalls) {
      expect(call.params.vulnTypes).toEqual(expect.arrayContaining([
        'waf_bypass',
        'redis_no_auth',
        'kubernetes_api_exposed',
        'database_exposed',
      ]))
    }
  })

  test('merges port-row + vuln-row on same (ip, port); merges vulnTags', async () => {
    // Simulate: port-row for 1.2.3.4:6379, vuln-row also for 1.2.3.4:6379
    const portRows = [{
      origin: 'port', ipAddress: '1.2.3.4', port: { low: 6379, high: 0 }, protocol: 'tcp',
      serviceName: 'redis', serviceProduct: null, serviceVersion: null,
      techs: ['redis 6.2'], subdomains: ['cache.a.com'],
      vulnTags: [], isCdn: false, cdnName: null, asn: 'AS1', country: 'US', organization: 'X',
    }]
    const vulnRows = [{
      origin: 'vuln', ipAddress: '1.2.3.4', port: { low: 6379, high: 0 }, protocol: 'tcp',
      serviceName: null, serviceProduct: null, serviceVersion: null,
      techs: [], subdomains: ['cache.a.com'],
      vulnTags: ['redis_no_auth'], isCdn: false, cdnName: null, asn: 'AS1', country: 'US', organization: 'X',
    }]
    const calls: any[] = []
    vi.resetModules()
    vi.doMock('@/app/api/graph/neo4j', () => ({
      getSession: () => ({
        run: async (cypher: string, params: any) => {
          calls.push({ cypher, params })
          const recs = (calls.length === 1 ? portRows : vulnRows).map(row => ({ get: (k: string) => (row as any)[k] }))
          return { records: recs }
        },
        close: async () => {},
      }),
    }))
    const mod = await import('./netInitAccess/route')
    const res = await mod.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(1)
    const r = body.rows[0]
    expect(r.ipAddress).toBe('1.2.3.4')
    expect(r.port).toBe(6379)
    expect(r.vulnTags).toContain('redis_no_auth')
    expect(r.category).toBe('database')   // 6379 → database
  })

  test('port category lookup maps common ports correctly', async () => {
    const rows = [
      { origin: 'port', ipAddress: '1.1.1.1', port: { low: 22, high: 0 }, protocol: 'tcp', serviceName: null, serviceProduct: null, serviceVersion: null, techs: [], subdomains: [], vulnTags: [], isCdn: null, cdnName: null, asn: null, country: null, organization: null },
      { origin: 'port', ipAddress: '1.1.1.2', port: { low: 3306, high: 0 }, protocol: 'tcp', serviceName: null, serviceProduct: null, serviceVersion: null, techs: [], subdomains: [], vulnTags: [], isCdn: null, cdnName: null, asn: null, country: null, organization: null },
      { origin: 'port', ipAddress: '1.1.1.3', port: { low: 10250, high: 0 }, protocol: 'tcp', serviceName: null, serviceProduct: null, serviceVersion: null, techs: [], subdomains: [], vulnTags: [], isCdn: null, cdnName: null, asn: null, country: null, organization: null },
    ]
    const calls: any[] = []
    vi.resetModules()
    vi.doMock('@/app/api/graph/neo4j', () => ({
      getSession: () => ({
        run: async () => {
          calls.push(1)
          const recs = (calls.length === 1 ? rows : []).map(row => ({ get: (k: string) => (row as any)[k] }))
          return { records: recs }
        },
        close: async () => {},
      }),
    }))
    const mod = await import('./netInitAccess/route')
    const res = await mod.GET(makeRequest('p1'))
    const body = await res.json()
    const byPort: Record<number, string> = {}
    for (const r of body.rows) byPort[r.port] = r.category
    expect(byPort[22]).toBe('ssh')
    expect(byPort[3306]).toBe('database')
    expect(byPort[10250]).toBe('k8s')
  })
})

// ---------------------------------------------------------------------------
// graphql: is_graphql filter + sort order
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/graphql', () => {
  test('Cypher filters Endpoint by is_graphql=true', async () => {
    runReturn = []
    await graphqlRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/MATCH \(ep:Endpoint \{project_id: \$pid\}\)/)
    expect(c).toMatch(/WHERE ep\.is_graphql = true/)
  })

  test('pulls graphql-* vulnerability sources', async () => {
    await graphqlRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/v\.source IN \['graphql_scan','graphql_cop'\]/)
  })

  test('sorts introspection-enabled endpoints first', async () => {
    await graphqlRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    // Uses CASE WHEN ep.graphql_introspection_enabled = true THEN 0 ELSE 1 END
    expect(c).toMatch(/CASE WHEN ep\.graphql_introspection_enabled = true THEN 0 ELSE 1 END/)
  })

  test('boolean graphql flags pass through unchanged', async () => {
    runReturn = [{
      endpointUrl: 'https://api/graphql',
      path: '/graphql',
      baseUrl: 'https://api',
      subdomain: 'api.example.com',
      introspection: true,
      graphiqlExposed: true,
      fieldSuggestions: false,
      getAllowed: false,
      batching: true,
      tracing: false,
      queriesCount: { low: 42, high: 0 },
      mutationsCount: { low: 11, high: 0 },
      subscriptionsCount: { low: 0, high: 0 },
      schemaHash: 'abc123',
      schemaExtractedAt: '2026-04-01T00:00:00Z',
      copScannedAt: '2026-04-02T00:00:00Z',
      lastError: null,
      sensitiveFieldsSample: 'password, token',
      vulnTypes: ['graphql_introspection_enabled', 'graphql_graphiql_exposed'],
      vulnSeverities: ['medium', 'high'],
    }]
    const res = await graphqlRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(1)
    const r = body.rows[0]
    expect(r.introspection).toBe(true)
    expect(r.graphiqlExposed).toBe(true)
    expect(r.fieldSuggestions).toBe(false)
    expect(r.queriesCount).toBe(42)
    expect(r.mutationsCount).toBe(11)
    expect(r.vulnTypes).toEqual(['graphql_introspection_enabled', 'graphql_graphiql_exposed'])
  })
})
