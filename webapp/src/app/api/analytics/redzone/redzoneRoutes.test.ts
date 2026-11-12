/**
 * Route handler tests for all 6 Red Zone endpoints.
 *
 * Strategy: mock `getGraphSession` to return a deterministic stub that:
 *   - captures the Cypher text + params so we can assert the query shape,
 *   - returns a list of fake records each supporting `.get(key)`.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/redzoneRoutes.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

// --- Mock neo4j module BEFORE importing route modules ---
const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runReturn: Array<Record<string, unknown>> = []
/** Rows returned only for a query whose Cypher matches. The secrets route runs
 *  TWO queries (the :Secret traversal and the MultiscannerFinding one); a flat
 *  `runReturn` would answer both and double every row. */
let runReturnFor: Array<{ match: RegExp; rows: Array<Record<string, unknown>> }> = []
let shouldThrow: Error | null = null

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      if (shouldThrow) throw shouldThrow
      const matched = runReturnFor.find(r => r.match.test(cypher))
      const rows = matched ? matched.rows : (runReturnFor.length ? [] : runReturn)
      const records = rows.map(row => ({
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
  runReturnFor = []
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
  ])('%s returns 500 when Neo4j throws, with a fixed message and no raw text', async (_, handler) => {
    shouldThrow = new Error('connection refused')
    const res = await handler(makeRequest('p1'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Query failed', code: 'internal_error' })
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
    expect(c).toMatch(/-\[dnsr:RESOLVES_TO\]->\(ip:IP\)\s+WHERE dnsr\.source IS NULL/)
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
  test("Cypher reads the takeover scan and item 5's two deleted-service page types", async () => {
    runReturn = []
    await takeoverRoute.GET(makeRequest('p1'))
    const c = runCalls[0].cypher
    expect(c).toMatch(/MATCH \(v:Vulnerability \{project_id: \$pid\}\)/)
    expect(c).toContain("v.source = 'takeover_scan'")
    expect(c).toContain("(v.source = 'urlscan_leak' AND v.type = 'takeover_page_seen')")
    expect(c).toContain("(v.source = 'security_check' AND v.type = 'takeover_error_page')")
  })

  test('labels who found each row and maps a problem-page outcome onto the verdict scale', async () => {
    runReturn = [
      { id: 'a', source: 'takeover_scan', hostname: 'a.example.test', verdict: 'confirmed', provider: 'heroku' },
      { id: 'b', source: 'urlscan_leak', hostname: 'b.example.test', outcome: 'likely_takeover', provider: 'surge', method: 'live_page' },
      { id: 'c', source: 'security_check', hostname: 'c.example.test', outcome: 'dangling_dns', provider: 'netlify' },
    ]
    const res = await takeoverRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows.map((r: { foundBy: string }) => r.foundBy))
      .toEqual(['takeover scan', 'urlscan history', 'live check'])
    expect(body.rows.map((r: { verdict: string }) => r.verdict)).toEqual(['confirmed', 'likely', 'manual_review'])
    expect(body.meta.likely).toBe(1)
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
// secrets: the :Secret traversal (BaseURL OR JsReconFinding) UNIONed with the
// MultiscannerFinding one, so a credential confirmed live is not graph-only.
// ---------------------------------------------------------------------------
describe('/api/analytics/redzone/secrets', () => {
  test('the Secret query traverses both HAS_SECRET paths', async () => {
    runReturn = []
    await secretsRoute.GET(makeRequest('p1'))
    const c = runCalls.find(call => /MATCH \(s:Secret/.test(call.cypher))!.cypher
    expect(c).toMatch(/MATCH \(s:Secret \{project_id: \$pid\}\)/)
    expect(c).toMatch(/\(buDirect:BaseURL\)-\[:HAS_SECRET\]->\(s\)/)
    expect(c).toMatch(/JsReconFinding.*finding_type: 'js_file'/s)
    expect(c).toMatch(/-\[:HAS_SECRET\]->\(s\)/)
    expect(c).toMatch(/\(buJs:BaseURL\)-\[:HAS_JS_FILE\]->\(j\)/)
  })

  test('a second query picks up Secret Multiscanner findings', async () => {
    runReturn = []
    await secretsRoute.GET(makeRequest('p1'))
    const c = runCalls.find(call => /MultiscannerFinding/.test(call.cypher))
    expect(c).toBeDefined()
    // Untyped asset match: assets carry one of five labels, and naming one
    // would silently drop every non-git source.
    expect(c!.cypher).toMatch(/OPTIONAL MATCH \(a\)-\[:HAS_FINDING\]->\(tf\)/)
    expect(c!.cypher).toMatch(/tf\.validation_status/)
    expect(c!.params.pid).toBe('p1')
  })

  test('sorts validated > format_validated > unvalidated then by type priority', async () => {
    runReturn = [
      { id: 's1', secretType: 'API Key', valueSample: 'k1', matchedText: null, entropy: 3.1, confidence: 'medium', severity: 'medium', sourceModule: 'js_recon', sourceUrl: 'http://a/app.js', secretBaseUrl: null, keyType: 'auth', detectionMethod: 'regex', validationStatus: 'unvalidated', baseUrl: 'http://a', subdomain: 'a.com', jsFileUrl: 'http://a/app.js', origin: 'JsReconFinding' },
      { id: 's2', secretType: 'AWS Secret Key', valueSample: 'akia...', matchedText: null, entropy: 4.8, confidence: 'high', severity: 'critical', sourceModule: 'resource_enum', sourceUrl: 'http://a/config.json', secretBaseUrl: null, keyType: 'cloud', detectionMethod: 'regex', validationStatus: 'validated', baseUrl: 'http://a', subdomain: 'a.com', jsFileUrl: null, origin: 'Secret' },
      { id: 's3', secretType: 'GitHub Token Classic', valueSample: 'ghp_', matchedText: null, entropy: 4.2, confidence: 'high', severity: 'high', sourceModule: 'js_recon', sourceUrl: 'http://a/app.js', secretBaseUrl: null, keyType: 'auth', detectionMethod: 'regex', validationStatus: 'format_validated', baseUrl: 'http://a', subdomain: 'a.com', jsFileUrl: 'http://a/app.js', origin: 'JsReconFinding' },
    ]
    runReturnFor = [{ match: /MATCH \(s:Secret/, rows: runReturn }]
    const res = await secretsRoute.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(3)
    // validated first, format_validated next, unvalidated last
    expect(body.rows[0].id).toBe('s2')   // AWS Secret Key, validated
    expect(body.rows[1].id).toBe('s3')   // GitHub Token, format_validated
    expect(body.rows[2].id).toBe('s1')   // API Key, unvalidated
  })

  test('a live Secret Multiscanner finding outranks every unvalidated :Secret row', async () => {
    // The point of surfacing them here: a credential the owning API CONFIRMED
    // works is the most actionable row in the table.
    runReturnFor = [
      { match: /MATCH \(s:Secret/, rows: [
        { id: 's1', secretType: 'API Key', validationStatus: 'unvalidated', origin: 'Secret' },
      ] },
      { match: /MultiscannerFinding/, rows: [
        { id: 'tf1', secretType: 'AWS', validationStatus: 'validated', trufflehogSource: 'docker',
          asset: 'acme/app:1.0', location: '/app/.env', findingKind: 'secret' },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows).toHaveLength(2)
    expect(body.rows[0].id).toBe('tf1')
    expect(body.rows[0].origin).toBe('MultiscannerFinding')
    expect(body.rows[0].severity).toBe('critical')
    expect(body.rows[0].trufflehogSource).toBe('docker')
  })

  test('a never-checked Secret Multiscanner finding ranks BELOW a checked-and-dead one', async () => {
    // 'unverified' means nobody looked; it must not read as "checked and safe".
    runReturnFor = [
      { match: /MATCH \(s:Secret/, rows: [] },
      { match: /MultiscannerFinding/, rows: [
        { id: 'never', secretType: 'AWS', validationStatus: 'unverified' },
        { id: 'dead', secretType: 'AWS', validationStatus: 'unvalidated' },
        { id: 'errored', secretType: 'AWS', validationStatus: 'verify_error' },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows.map((r: { id: string }) => r.id)).toEqual(['errored', 'dead', 'never'])
  })

  test('N+1 guard: one query per source regardless of how many rows come back', async () => {
    // Every traversal is set-based. A per-row lookup creeping in (to resolve an
    // asset name, say) would show up here as query count scaling with rows.
    runReturnFor = [
      { match: /MATCH \(s:Secret/, rows: Array.from({ length: 50 }, (_, i) => ({
        id: `s${i}`, secretType: 'API Key', validationStatus: 'unvalidated', origin: 'Secret',
      })) },
      { match: /MultiscannerFinding/, rows: Array.from({ length: 50 }, (_, i) => ({
        id: `tf${i}`, secretType: 'AWS', validationStatus: 'validated', trufflehogSource: 'docker',
      })) },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows).toHaveLength(100)
    // :Secret, MultiscannerFinding, GithubSecret, GithubSensitiveFile, ChainFinding
    expect(runCalls).toHaveLength(5)
  })

  // -- the three sources this table used to omit ----------------------------
  // Every one of them was graph-only: the operator had to open /graph to see a
  // credential RedAmon had already found.

  test('GitHub Secret Hunt findings are queried', async () => {
    await secretsRoute.GET(makeRequest('p1'))
    const c = runCalls.find(call => /MATCH \(gs:GithubSecret/.test(call.cypher))
    expect(c).toBeDefined()
    expect(c!.cypher).toMatch(/\(gp:GithubPath\)-\[:CONTAINS_SECRET\]->\(gs\)/)
    expect(c!.params.pid).toBe('p1')
  })

  test('GitHub sensitive FILES are queried too, and carry no value', async () => {
    runReturnFor = [
      { match: /GithubSensitiveFile/, rows: [
        { id: 'gf1', asset: 'acme/app', location: '.env', updatedAt: null },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows).toHaveLength(1)
    expect(body.rows[0].origin).toBe('GithubSensitiveFile')
    // The scanner never opened the file, so claiming a sample would be a lie.
    expect(body.rows[0].valueSample).toBeNull()
    expect(body.rows[0].location).toBe('.env')
    expect(body.rows[0].severity).toBe('low')
  })

  test('a GitHub secret is never marked as checked', async () => {
    // Pure regex, no verification step. `unvalidated` would read as
    // checked-and-dead, which nobody established.
    runReturnFor = [
      { match: /MATCH \(gs:GithubSecret/, rows: [
        { id: 'g1', secretType: 'AWS Access Key ID', valueSample: 'AKIA', matches: 3,
          asset: 'acme/app', location: 'src/config.py', updatedAt: null },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows[0].validationStatus).toBe('unverified')
    expect(body.rows[0].sourceModule).toBe('github_hunt')
    expect(body.rows[0].asset).toBe('acme/app')
    expect(body.rows[0].confidence).toBe(3)
  })

  test('GitHub severity separates a key from a private IP address', async () => {
    // A full-org scan is mostly low-value families; flattening them all to one
    // severity buries the findings that matter.
    runReturnFor = [
      { match: /MATCH \(gs:GithubSecret/, rows: [
        { id: 'ip', secretType: 'IP Address (Private)', asset: 'a', location: 'b' },
        { id: 'pg', secretType: 'PostgreSQL Connection String', asset: 'a', location: 'b' },
        { id: 'pw', secretType: 'Hardcoded Password', asset: 'a', location: 'b' },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    const bySev = Object.fromEntries(body.rows.map((r: { id: string, severity: string }) => [r.id, r.severity]))
    expect(bySev).toEqual({ ip: 'low', pg: 'high', pw: 'medium' })
  })

  test('a credential hidden in a URL is not filed as low', async () => {
    // `redis://user:pass@`, `cloudinary://key:secret@` and
    // `https://user:token@github.com` carry inline auth that no keyword in the
    // pattern NAME gives away, so they need naming explicitly.
    runReturnFor = [
      { match: /MATCH \(gs:GithubSecret/, rows: [
        { id: 'ghcred', secretType: 'GitHub Credentials URL', asset: 'a', location: 'b' },
        { id: 'redis', secretType: 'Redis URL', asset: 'a', location: 'b' },
        { id: 'cloudinary', secretType: 'Cloudinary URL', asset: 'a', location: 'b' },
        { id: 'p12', secretType: 'PKCS12 File', asset: 'a', location: 'b' },
        // Publishable by design: info, below every credential (plan 05.2).
        { id: 'recaptcha', secretType: 'Google reCAPTCHA Key', asset: 'a', location: 'b' },
        { id: 'bucket', secretType: 'S3 Bucket (virtual-hosted)', asset: 'a', location: 'b' },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    const bySev = Object.fromEntries(body.rows.map((r: { id: string, severity: string }) => [r.id, r.severity]))
    expect(bySev).toEqual({
      ghcred: 'high', redis: 'high', cloudinary: 'high', p12: 'high',
      recaptcha: 'info', bucket: 'low',
    })
  })

  test('a key that is public by design is info and flagged, by flag or by name (plan 05.2)', async () => {
    runReturnFor = [
      { match: /MATCH \(s:Secret/, rows: [
        { id: 'flagged', secretType: 'GCP API Key', severity: 'info', publicClientKey: true, origin: 'Secret' },
        // Written before the flag existed: still stored critical.
        { id: 'legacy', secretType: 'GCP API Key', severity: 'critical', publicClientKey: null, origin: 'Secret' },
        { id: 'secret', secretType: 'Stripe Secret Key', severity: 'critical', publicClientKey: false, origin: 'Secret' },
      ] },
      { match: /MATCH \(gs:GithubSecret/, rows: [
        { id: 'gh-pub', secretType: 'Stripe Publishable Key', asset: 'a', location: 'b' },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    const byId = Object.fromEntries(body.rows.map((r: { id: string }) => [r.id, r]))
    expect([byId.flagged.severity, byId.flagged.publicClientKey]).toEqual(['info', true])
    expect([byId.legacy.severity, byId.legacy.publicClientKey]).toEqual(['info', true])
    expect([byId.secret.severity, byId.secret.publicClientKey]).toEqual(['critical', false])
    expect([byId['gh-pub'].severity, byId['gh-pub'].publicClientKey]).toEqual(['info', true])
    const c = runCalls.find(call => /MATCH \(s:Secret/.test(call.cypher))!.cypher
    expect(c).toMatch(/s\.public_client_key\s+AS publicClientKey/)
  })

  test('a TruffleHog credential checked and dead sorts the same under either word (plan 05.8)', async () => {
    runReturnFor = [
      { match: /MATCH \(s:Secret/, rows: [] },
      { match: /MultiscannerFinding/, rows: [
        { id: 'never', secretType: 'AWS', validationStatus: 'unverified' },
        { id: 'dead-new', secretType: 'AWS', validationStatus: 'rejected' },
        { id: 'errored', secretType: 'AWS', validationStatus: 'verify_error' },
        { id: 'dead-old', secretType: 'AWS', validationStatus: 'unvalidated' },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows.map((r: { id: string }) => r.id)).toEqual(['errored', 'dead-new', 'dead-old', 'never'])
  })

  test('the explicit validation states sort as they read (plan 05.7)', async () => {
    // No verdict ranks above a dead key; a legacy 'invalid' keeps its old place.
    runReturnFor = [
      { match: /MATCH \(s:Secret/, rows: [
        { id: 'legacy', secretType: 'API Key', validationStatus: 'invalid', origin: 'Secret' },
        { id: 'dead', secretType: 'API Key', validationStatus: 'rejected', origin: 'Secret' },
        { id: 'nocheck', secretType: 'API Key', validationStatus: 'unknown', origin: 'Secret' },
        { id: 'live', secretType: 'API Key', validationStatus: 'validated', origin: 'Secret' },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows.map((r: { id: string }) => r.id)).toEqual(['live', 'nocheck', 'dead', 'legacy'])
  })

  test('a credential the agent USED outranks every scanner finding', async () => {
    // An exploit_success carrying a password is a credential someone logged in
    // with — the strongest row this table can hold.
    runReturnFor = [
      { match: /MultiscannerFinding/, rows: [
        { id: 'tf1', secretType: 'AWS', validationStatus: 'validated' },
      ] },
      { match: /MATCH \(f:ChainFinding/, rows: [
        { id: 'c1', findingType: 'exploit_success', username: 'admin', password: 'hunter2',
          attackType: 'sql_injection', severity: 'critical', targetIp: '10.0.0.5',
          targetPort: 8080, title: 'Exploit success', updatedAt: null },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows[0].id).toBe('c1')
    expect(body.rows[0].origin).toBe('ChainFinding')
    expect(body.rows[0].validationStatus).toBe('validated')
    expect(body.rows[0].secretType).toBe('Credential Pair')
    expect(body.rows[0].asset).toBe('10.0.0.5:8080')
    expect(body.rows[0].location).toBe('user: admin')
    expect(body.rows[0].keyType).toBe('sql_injection')
  })

  test('a merely OBSERVED credential is not claimed as proven', async () => {
    runReturnFor = [
      { match: /MATCH \(f:ChainFinding/, rows: [
        { id: 'c1', findingType: 'credential_found', username: 'svc', password: 'p',
          severity: 'high' },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows[0].validationStatus).toBe('unvalidated')
  })

  test('the chain query matches on the property, not only on finding_type', async () => {
    // The writer attaches username/password to exploit_success as well as
    // credential_found; keying off the type alone misses the ones that worked.
    await secretsRoute.GET(makeRequest('p1'))
    const c = runCalls.find(call => /MATCH \(f:ChainFinding/.test(call.cypher))!.cypher
    expect(c).toMatch(/f\.username IS NOT NULL OR f\.password IS NOT NULL/)
    expect(c).toMatch(/f\.finding_type = 'credential_found'/)
  })

  test('a Secret Multiscanner file finding is pinned to its line and commit', async () => {
    // Both were stored on the node and never surfaced, leaving the reader to
    // search the file by hand.
    runReturnFor = [
      { match: /MultiscannerFinding/, rows: [
        { id: 'tf1', secretType: 'AWS', location: 'src/app.py', line: 42,
          commit: 'abcdef1234567890', findingKind: 'secret' },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows[0].location).toBe('src/app.py:42 @abcdef1')
  })

  test('every query is scoped to the requested project', async () => {
    await secretsRoute.GET(makeRequest('p1'))
    for (const call of runCalls) {
      expect(call.params.pid).toBe('p1')
      expect(call.cypher).toContain('project_id: $pid')
    }
  })

  test('a Secret Multiscanner row with no asset or location does not break the response', async () => {
    runReturnFor = [
      { match: /MATCH \(s:Secret/, rows: [] },
      // The driver projects every RETURN column, so an absent value arrives as
      // null rather than missing; the fixture mirrors that.
      { match: /MultiscannerFinding/, rows: [{
        id: 'tf1', secretType: 'AWS', validationStatus: null, trufflehogSource: null,
        asset: null, location: null, findingKind: null, valueSample: null, sourceUrl: null,
      }] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows).toHaveLength(1)
    expect(body.rows[0].asset).toBeNull()
    expect(body.rows[0].origin).toBe('MultiscannerFinding')
    expect(body.rows[0].severity).toBe('medium')
  })

  test('a build-history finding shows a name, not a path that does not exist', async () => {
    runReturnFor = [
      { match: /MATCH \(s:Secret/, rows: [] },
      { match: /MultiscannerFinding/, rows: [
        { id: 'tf1', secretType: 'AWS', validationStatus: 'validated',
          location: 'image-metadata:history:3:created-by', findingKind: 'image_history' },
      ] },
    ]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    expect(body.rows[0].location).toBe('Dockerfile (build history)')
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

  test('a js_recon Secret only TruffleHog found is labelled TruffleHog (JS Recon)', async () => {
    // A key both engines found keeps js_recon's row and label; only the
    // TruffleHog-only one changes, and its detection stays machine-readable.
    runReturnFor = [{ match: /MATCH \(s:Secret/, rows: [
      { id: 'th', secretType: 'GitHub Token Classic', sourceModule: 'js_recon', detectionMethod: 'trufflehog',
        validationStatus: 'unknown', origin: 'JsReconFinding' },
      { id: 'rx', secretType: 'GitHub Token Classic', sourceModule: 'js_recon', detectionMethod: 'regex',
        validationStatus: 'unknown', origin: 'JsReconFinding' },
      { id: 'old', secretType: 'GitHub Token Classic', sourceModule: 'js_recon', detectionMethod: null,
        validationStatus: 'unknown', origin: 'JsReconFinding' },
    ] }]
    const body = await (await secretsRoute.GET(makeRequest('p1'))).json()
    const byId = Object.fromEntries(body.rows.map((r: any) => [r.id, r]))
    expect(byId.th.sourceModule).toBe('TruffleHog (JS Recon)')
    expect(byId.th.detectionMethod).toBe('trufflehog')
    expect(byId.rx.sourceModule).toBe('js_recon')
    expect(byId.old.sourceModule).toBe('js_recon')
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
      getGraphSession: () => ({
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
      getGraphSession: () => ({
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

// ---------------------------------------------------------------------------
// Node ID: every query that feeds rows projects the id of the node the row is
// about, and the mapper carries it through. A query that forgets it renders a
// silent `-` column, so each one is checked, not just the first.
// ---------------------------------------------------------------------------
describe('nodeId column', () => {
  test.each([
    ['killChain', killChainRoute.GET, 1],
    ['blastRadius', blastRadiusRoute.GET, 1],
    ['takeover', takeoverRoute.GET, 1],
    ['secrets', secretsRoute.GET, 5],
    ['netInitAccess', netInitAccessRoute.GET, 2],
    ['graphql', graphqlRoute.GET, 1],
  ])('%s projects nodeId in every row query', async (_, handler, queries) => {
    await handler(makeRequest('p1'))
    expect(runCalls).toHaveLength(queries)
    for (const call of runCalls) expect(call.cypher).toMatch(/\bAS nodeId\b/)
  })

  test.each([
    ['killChain', killChainRoute.GET, [/toString\(id\(tech\)\)\s+AS nodeId/]],
    ['blastRadius', blastRadiusRoute.GET, [/toString\(id\(t\)\)\s+AS nodeId/]],
    ['takeover', takeoverRoute.GET, [/toString\(id\(v\)\)\s+AS nodeId/]],
    ['secrets', secretsRoute.GET, [
      /toString\(id\(s\)\)\s+AS nodeId/,
      /toString\(id\(tf\)\)\s+AS nodeId/,
      /toString\(id\(gs\)\)\s+AS nodeId/,
      /toString\(id\(gsf\)\)\s+AS nodeId/,
      /toString\(id\(f\)\)\s+AS nodeId/,
    ]],
    ['netInitAccess', netInitAccessRoute.GET, [
      /toString\(id\(p\)\)\s+AS nodeId/,
      /count\(DISTINCT v\) WHEN 1 THEN toString\(id\(head\(collect\(v\)\)\)\)/,
    ]],
    ['graphql', graphqlRoute.GET, [/toString\(id\(ep\)\)\s+AS nodeId/]],
  ])('%s anchors each query on the node its row is about', async (_, handler, anchors) => {
    await handler(makeRequest('p1'))
    anchors.forEach((re, i) => expect(runCalls[i].cypher).toMatch(re))
  })

  test('killChain never anchors on the CVE, which MCP cannot address by id', async () => {
    // CVE nodes are global: the tenant filter MCP injects into `(n)` can never
    // match one, so an id(c) would read as a dead node to an external agent.
    await killChainRoute.GET(makeRequest('p1'))
    expect(runCalls[0].cypher).not.toMatch(/id\(c\)/)
  })

  test.each([
    ['killChain', killChainRoute.GET],
    ['blastRadius', blastRadiusRoute.GET],
    ['takeover', takeoverRoute.GET],
    ['secrets', secretsRoute.GET],
    ['netInitAccess', netInitAccessRoute.GET],
    ['graphql', graphqlRoute.GET],
  ])('%s maps nodeId onto every row, and a missing one to null', async (_, handler) => {
    runReturn = [{ nodeId: '4242' }]
    const withId = await (await handler(makeRequest('p1'))).json()
    expect(withId.rows.length).toBeGreaterThan(0)
    for (const row of withId.rows) expect(row.nodeId).toBe('4242')

    runCalls.length = 0
    runReturn = [{}]
    const without = await (await handler(makeRequest('p1'))).json()
    for (const row of without.rows) expect(row).toHaveProperty('nodeId', null)
  })

  test('netInitAccess: a vuln row merged into a port row keeps the Port id', async () => {
    runReturnFor = [
      { match: /'port'\s+AS origin/, rows: [
        { nodeId: '10', ipAddress: '1.2.3.4', port: { low: 6379, high: 0 }, vulnTags: [] },
      ] },
      { match: /'vuln'\s+AS origin/, rows: [
        { nodeId: '20', ipAddress: '1.2.3.4', port: { low: 6379, high: 0 }, vulnTags: ['redis_no_auth'] },
        { nodeId: '30', ipAddress: '5.6.7.8', port: null, vulnTags: ['waf_bypass'] },
      ] },
    ]
    const body = await (await netInitAccessRoute.GET(makeRequest('p1'))).json()
    const byIp = Object.fromEntries(body.rows.map((r: { ipAddress: string, nodeId: string }) => [r.ipAddress, r.nodeId]))
    expect(byIp).toEqual({ '1.2.3.4': '10', '5.6.7.8': '30' })
  })

  test('netInitAccess: finding rows merged on one ip:port point at the IP, not the first finding', async () => {
    // Part B groups on the finding's timestamp, so three findings on one host a
    // few ms apart arrive as three one-finding rows and the JS merge folds them.
    // The merged row lists all three tags; its id must not name just one of them.
    runReturnFor = [
      { match: /'port'\s+AS origin/, rows: [] },
      { match: /'vuln'\s+AS origin/, rows: [
        { nodeId: '535', ipNodeId: '7', ipAddress: '1.2.3.4', port: null, vulnTags: ['waf_bypass'] },
        { nodeId: '534', ipNodeId: '7', ipAddress: '1.2.3.4', port: null, vulnTags: ['direct_ip_https'] },
        { nodeId: '533', ipNodeId: '7', ipAddress: '1.2.3.4', port: null, vulnTags: ['direct_ip_http'] },
        { nodeId: '600', ipNodeId: '8', ipAddress: '5.6.7.8', port: null, vulnTags: ['waf_bypass'] },
      ] },
    ]
    const body = await (await netInitAccessRoute.GET(makeRequest('p1'))).json()
    const merged = body.rows.find((r: { ipAddress: string }) => r.ipAddress === '1.2.3.4')
    expect(merged.vulnTags).toEqual(['waf_bypass', 'direct_ip_https', 'direct_ip_http'])
    expect(merged.nodeId).toBe('7')
    // A lone finding still points at itself.
    expect(body.rows.find((r: { ipAddress: string }) => r.ipAddress === '5.6.7.8').nodeId).toBe('600')
    // The merge key is internal; it must not reach the table or its exports.
    for (const r of body.rows) expect(r).not.toHaveProperty('ipNodeId')
  })

  test('netInitAccess projects the IP id beside each finding row, for the merge', async () => {
    await netInitAccessRoute.GET(makeRequest('p1'))
    expect(runCalls[1].cypher).toMatch(/toString\(id\(head\(collect\(ip\)\)\)\)\s+AS ipNodeId/)
  })
})
