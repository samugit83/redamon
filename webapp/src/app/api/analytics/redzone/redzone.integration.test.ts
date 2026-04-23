/**
 * Integration test for all 6 Red Zone endpoints.
 *
 * Proves that the Cypher queries navigate a real Neo4j graph correctly.
 *
 * Strategy:
 *   1. Seed Neo4j with a minimal but complete graph topology under a dedicated
 *      test project_id, exercising every relationship each table expects.
 *   2. Call each HTTP endpoint via fetch() using the x-internal-key bypass.
 *   3. Assert exact row content.
 *   4. Clean up all nodes/edges under the test project_id afterwards.
 *
 * Requirements:
 *   - Webapp + Neo4j containers running (docker compose up -d webapp neo4j)
 *   - INTERNAL_API_KEY and NEO4J_PASSWORD available via env or webapp container.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/redzone.integration.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import neo4j, { Driver, Session } from 'neo4j-driver'

const NEO4J_URI      = process.env.NEO4J_URI      || 'bolt://localhost:7687'
const NEO4J_USER     = process.env.NEO4J_USER     || 'neo4j'
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || 'password'
const WEBAPP_URL     = process.env.REDZONE_TEST_WEBAPP_URL || 'http://localhost:3000'
const INTERNAL_KEY   = process.env.INTERNAL_API_KEY
const PROJECT_ID     = `redzone-itest-${Date.now()}`
const USER_ID        = 'redzone-itest-user'

let driver: Driver
let session: Session

async function run(cypher: string, params: Record<string, unknown> = {}): Promise<void> {
  await session.run(cypher, params)
}

async function fetchRedZone(slug: string): Promise<any> {
  if (!INTERNAL_KEY) throw new Error('INTERNAL_API_KEY env required')
  const res = await fetch(`${WEBAPP_URL}/api/analytics/redzone/${slug}?projectId=${PROJECT_ID}`, {
    headers: { 'x-internal-key': INTERNAL_KEY },
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`GET ${slug} → ${res.status}: ${text}`)
  }
  return res.json()
}

// ---------------------------------------------------------------------------
// Skip suite if prerequisites aren't available
// ---------------------------------------------------------------------------
const skipSuite = !INTERNAL_KEY

beforeAll(async () => {
  if (skipSuite) return
  driver = neo4j.driver(NEO4J_URI, neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD))
  session = driver.session()

  // Verify Neo4j connectivity
  await driver.verifyConnectivity()

  // Make sure we start clean
  await run(
    `MATCH (n {project_id: $pid}) DETACH DELETE n`,
    { pid: PROJECT_ID },
  )

  await seedGraph()
}, 30_000)

afterAll(async () => {
  if (skipSuite) return
  try {
    await run(
      `MATCH (n {project_id: $pid}) DETACH DELETE n`,
      { pid: PROJECT_ID },
    )
  } finally {
    await session?.close()
    await driver?.close()
  }
}, 30_000)

// ---------------------------------------------------------------------------
// Graph seed: covers all 6 red-zone tables
// ---------------------------------------------------------------------------
async function seedGraph() {
  const p = { pid: PROJECT_ID, uid: USER_ID }

  // ----- Kill-chain + blast-radius backbone -----
  // Domain -> Subdomain -> IP -> Port -> Service -> Technology -> CVE -> MitreData -> Capec
  // Plus ExploitGvm marking one CVE as CISA KEV.
  await run(`
    MERGE (d:Domain      {name: 'example.com',       user_id: $uid, project_id: $pid})
    MERGE (sd:Subdomain  {name: 'api.example.com',   user_id: $uid, project_id: $pid})
    MERGE (sd2:Subdomain {name: 'admin.example.com', user_id: $uid, project_id: $pid})
    MERGE (d)-[:HAS_SUBDOMAIN]->(sd)
    MERGE (d)-[:HAS_SUBDOMAIN]->(sd2)
    MERGE (ip:IP         {address: '203.0.113.10',  user_id: $uid, project_id: $pid})
    MERGE (sd)-[:RESOLVES_TO]->(ip)
    MERGE (sd2)-[:RESOLVES_TO]->(ip)
    MERGE (p443:Port     {number: 443,   protocol: 'tcp', ip_address: '203.0.113.10', state: 'open', user_id: $uid, project_id: $pid})
    MERGE (ip)-[:HAS_PORT]->(p443)
    MERGE (svc:Service   {name: 'HTTPS', port_number: 443, ip_address: '203.0.113.10', user_id: $uid, project_id: $pid})
    MERGE (p443)-[:RUNS_SERVICE]->(svc)
    MERGE (t:Technology  {name: 'nginx', version: '1.18', user_id: $uid, project_id: $pid})
    MERGE (svc)-[:USES_TECHNOLOGY]->(t)
    MERGE (p443)-[:HAS_TECHNOLOGY]->(t)
    MERGE (bu:BaseURL    {url: 'https://api.example.com', scheme: 'https', host: 'api.example.com', user_id: $uid, project_id: $pid})
    MERGE (bu)-[:USES_TECHNOLOGY]->(t)
    MERGE (cve1:CVE      {id: $pid + '-CVE-2023-NGINX-1'})
      ON CREATE SET cve1.cvss = 9.8, cve1.severity = 'critical', cve1.user_id = $uid, cve1.project_id = $pid
    MERGE (cve2:CVE      {id: $pid + '-CVE-2023-NGINX-2'})
      ON CREATE SET cve2.cvss = 7.5, cve2.severity = 'high',     cve2.user_id = $uid, cve2.project_id = $pid
    MERGE (t)-[:HAS_KNOWN_CVE]->(cve1)
    MERGE (t)-[:HAS_KNOWN_CVE]->(cve2)
    MERGE (m:MitreData   {id: $pid + '-CWE-79-m'})
      ON CREATE SET m.cve_id = $pid + '-CVE-2023-NGINX-1', m.cwe_id = 'CWE-79', m.cwe_name = 'XSS', m.user_id = $uid, m.project_id = $pid
    MERGE (cve1)-[:HAS_CWE]->(m)
    MERGE (cap:Capec     {capec_id: $pid + '-CAPEC-63'})
      ON CREATE SET cap.name = 'Reflected XSS', cap.severity = 'High', cap.user_id = $uid, cap.project_id = $pid
    MERGE (m)-[:HAS_CAPEC]->(cap)
    MERGE (ex:ExploitGvm {id: $pid + '-exgvm-1'})
      ON CREATE SET ex.target_ip = '203.0.113.10', ex.target_port = 443, ex.cvss_score = 9.8, ex.user_id = $uid, ex.project_id = $pid
    MERGE (ex)-[:EXPLOITED_CVE]->(cve1)
  `, p)

  // ----- Second tech (lower risk, no KEV) to validate blast-radius ordering -----
  await run(`
    MERGE (t2:Technology {name: 'apache', version: '2.4.1', user_id: $uid, project_id: $pid})
    MERGE (bu:BaseURL {url: 'https://api.example.com', user_id: $uid, project_id: $pid})
    MERGE (bu)-[:USES_TECHNOLOGY]->(t2)
    MERGE (cveA:CVE {id: $pid + '-CVE-2023-APACHE-1'})
      ON CREATE SET cveA.cvss = 5.4, cveA.severity = 'medium', cveA.user_id = $uid, cveA.project_id = $pid
    MERGE (t2)-[:HAS_KNOWN_CVE]->(cveA)
  `, p)

  // ----- Subdomain Takeover -----
  await run(`
    MERGE (dangling:Subdomain {name: 'status.example.com', user_id: $uid, project_id: $pid})
    MERGE (vConfirmed:Vulnerability {
      id: 'takeover_confirmed_1', source: 'takeover_scan', type: 'subdomain_takeover',
      hostname: 'status.example.com', cname_target: 'examplestatus.github.io',
      takeover_provider: 'github-pages', takeover_method: 'cname',
      verdict: 'confirmed', confidence: 90, severity: 'high',
      sources: ['subjack', 'nuclei_takeover'], confirmation_count: 2,
      evidence: 'There isn\\'t a GitHub Pages site here', first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-04-20T00:00:00Z',
      user_id: $uid, project_id: $pid
    })
    MERGE (dangling)-[:HAS_VULNERABILITY]->(vConfirmed)
    MERGE (vLikely:Vulnerability {id: 'takeover_likely_1', project_id: $pid})
      ON CREATE SET
        vLikely.source = 'takeover_scan', vLikely.type = 'subdomain_takeover',
        vLikely.hostname = 'mail.example.com',
        vLikely.takeover_provider = 'unknown', vLikely.takeover_method = 'mx',
        vLikely.verdict = 'likely', vLikely.confidence = 65, vLikely.severity = 'medium',
        vLikely.sources = ['baddns'], vLikely.confirmation_count = 1,
        vLikely.user_id = $uid
    MERGE (mailSd:Subdomain {name: 'mail.example.com', user_id: $uid, project_id: $pid})
    MERGE (mailSd)-[:HAS_VULNERABILITY]->(vLikely)
    MERGE (vManual:Vulnerability {
      id: 'takeover_manual_1', source: 'takeover_scan', type: 'subdomain_takeover',
      hostname: 'legacy.example.com', cname_target: 'old.herokuapp.com',
      takeover_provider: 'heroku', takeover_method: 'stale_a',
      verdict: 'manual_review', confidence: 40, severity: 'info',
      sources: ['baddns'], confirmation_count: 1,
      user_id: $uid, project_id: $pid
    })
    MERGE (legSd:Subdomain {name: 'legacy.example.com', user_id: $uid, project_id: $pid})
    MERGE (legSd)-[:HAS_VULNERABILITY]->(vManual)
  `, p)

  // ----- Secrets live in :Secret nodes, attached two ways -----
  //   (BaseURL)-[:HAS_SECRET]->(Secret)                         (resource_enum)
  //   (JsReconFinding{js_file})-[:HAS_SECRET]->(Secret)         (js_recon)
  await run(`
    MERGE (bu:BaseURL {url: 'https://api.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdApi:Subdomain {name: 'api.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdApi)-[:HAS_BASE_URL]->(bu)

    MERGE (secAws:Secret {id: 'sec-aws-1', project_id: $pid})
      ON CREATE SET
        secAws.secret_type = 'AWS Secret Key',
        secAws.key_type = 'cloud',
        secAws.sample = 'AKIA***REDACTED***',
        secAws.matched_text = 'AKIA5FAKEACCESSKEYZ',
        secAws.entropy = 4.8,
        secAws.confidence = 'high',
        secAws.severity = 'critical',
        secAws.source = 'resource_enum',
        secAws.source_url = 'https://api.example.com/config.json',
        secAws.base_url = 'https://api.example.com',
        secAws.detection_method = 'regex',
        secAws.validation_status = 'validated',
        secAws.user_id = $uid
    MERGE (bu)-[:HAS_SECRET]->(secAws)

    MERGE (jsFile:JsReconFinding {id: 'jrf-jsfile-app', project_id: $pid})
      ON CREATE SET
        jsFile.finding_type = 'js_file',
        jsFile.source_url = 'https://api.example.com/app.js',
        jsFile.base_url = 'https://api.example.com',
        jsFile.source = 'js_recon',
        jsFile.severity = 'info',
        jsFile.confidence = 'high',
        jsFile.user_id = $uid
    MERGE (bu)-[:HAS_JS_FILE]->(jsFile)

    MERGE (secGh:Secret {id: 'sec-gh-1', project_id: $pid})
      ON CREATE SET
        secGh.secret_type = 'GitHub Token Classic',
        secGh.key_type = 'auth',
        secGh.sample = 'ghp_***REDACTED***',
        secGh.matched_text = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
        secGh.entropy = 4.2,
        secGh.confidence = 'high',
        secGh.severity = 'high',
        secGh.source = 'js_recon',
        secGh.source_url = 'https://api.example.com/app.js',
        secGh.base_url = 'https://api.example.com',
        secGh.detection_method = 'regex',
        secGh.validation_status = 'format_validated',
        secGh.user_id = $uid
    MERGE (jsFile)-[:HAS_SECRET]->(secGh)
  `, p)

  // ----- Network Initial-Access (sensitive ports + waf bypass) -----
  await run(`
    MERGE (ip2:IP {address: '203.0.113.20', user_id: $uid, project_id: $pid, is_cdn: false, asn: 'AS99', country: 'US', organization: 'Example ISP'})
    MERGE (p6379:Port {number: 6379, protocol: 'tcp', ip_address: '203.0.113.20', state: 'open', user_id: $uid, project_id: $pid})
    MERGE (ip2)-[:HAS_PORT]->(p6379)
    MERGE (svcRedis:Service {name: 'redis', port_number: 6379, ip_address: '203.0.113.20', product: 'Redis', user_id: $uid, project_id: $pid})
    MERGE (p6379)-[:RUNS_SERVICE]->(svcRedis)
    MERGE (sdCache:Subdomain {name: 'cache.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdCache)-[:RESOLVES_TO]->(ip2)
    MERGE (redisVuln:Vulnerability {id: 'redis-unauth-1', project_id: $pid})
      ON CREATE SET
        redisVuln.source = 'security_check', redisVuln.type = 'redis_no_auth',
        redisVuln.name = 'Redis Without Authentication', redisVuln.severity = 'critical',
        redisVuln.matched_ip = '203.0.113.20', redisVuln.port = 6379,
        redisVuln.user_id = $uid
    MERGE (ip2)-[:HAS_VULNERABILITY]->(redisVuln)

    MERGE (ip3:IP {address: '203.0.113.30', user_id: $uid, project_id: $pid})
      ON CREATE SET ip3.is_cdn = true, ip3.cdn = 'Cloudflare', ip3.asn = 'AS13335', ip3.country = 'US'
    MERGE (wafVuln:Vulnerability {id: 'waf-bypass-1', project_id: $pid})
      ON CREATE SET
        wafVuln.source = 'security_check', wafVuln.type = 'waf_bypass',
        wafVuln.name = 'WAF Bypass via Direct IP Access', wafVuln.severity = 'high',
        wafVuln.matched_ip = '203.0.113.30',
        wafVuln.user_id = $uid
    MERGE (ip3)-[:HAS_VULNERABILITY]->(wafVuln)
  `, p)

  // ----- GraphQL Risk Ledger -----
  await run(`
    MERGE (buApi:BaseURL {url: 'https://api.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdApi:Subdomain {name: 'api.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdApi)-[:HAS_BASE_URL]->(buApi)
    MERGE (epGql:Endpoint {
      path: '/graphql', method: 'POST', baseurl: 'https://api.example.com',
      full_url: 'https://api.example.com/graphql',
      is_graphql: true,
      graphql_introspection_enabled: true,
      graphql_graphiql_exposed: true,
      graphql_field_suggestions_enabled: true,
      graphql_get_allowed: false,
      graphql_batching_enabled: true,
      graphql_tracing_enabled: false,
      graphql_queries_count: 42,
      graphql_mutations_count: 11,
      graphql_subscriptions_count: 0,
      graphql_schema_hash: 'sha256:abc123',
      sensitive_fields_sample: 'password, token, apiKey',
      user_id: $uid, project_id: $pid
    })
    MERGE (buApi)-[:HAS_ENDPOINT]->(epGql)
    MERGE (gqlVuln:Vulnerability {
      id: 'gql-introspection-1',
      vulnerability_type: 'graphql_introspection_enabled',
      source: 'graphql_cop',
      severity: 'medium',
      graphql_cop_key: 'graphql_introspection_enabled',
      user_id: $uid, project_id: $pid
    })
    MERGE (epGql)-[:HAS_VULNERABILITY]->(gqlVuln)

    MERGE (epNotGql:Endpoint {
      path: '/rest/users', method: 'GET', baseurl: 'https://api.example.com',
      is_graphql: false,
      user_id: $uid, project_id: $pid
    })
    MERGE (buApi)-[:HAS_ENDPOINT]->(epNotGql)
  `, p)
}

// ---------------------------------------------------------------------------
// Tests: each verifies the queries return exactly the expected seeded shape
// ---------------------------------------------------------------------------
describe.skipIf(skipSuite)('Red Zone integration: live Neo4j + HTTP', () => {
  test('killChain: walks Subdomain → IP → Port → Service → Technology → CVE → CWE → CAPEC', async () => {
    const body = await fetchRedZone('killChain')
    expect(body.rows.length).toBeGreaterThanOrEqual(2)   // nginx has 2 CVEs

    const nginxCrit = body.rows.find((r: any) => r.cveId === `${PROJECT_ID}-CVE-2023-NGINX-1`)
    expect(nginxCrit).toBeDefined()
    expect(nginxCrit.subdomain).toBe('api.example.com')
    expect(nginxCrit.ipAddress).toBe('203.0.113.10')
    expect(nginxCrit.port).toBe(443)
    expect(nginxCrit.protocol).toBe('tcp')
    expect(nginxCrit.serviceName).toBe('HTTPS')
    expect(nginxCrit.techName).toBe('nginx')
    expect(nginxCrit.techVersion).toBe('1.18')
    expect(nginxCrit.cvss).toBe(9.8)
    expect(nginxCrit.cveSeverity).toBe('critical')
    expect(nginxCrit.cisaKev).toBe(true)
    expect(nginxCrit.cweId).toBe('CWE-79')
    expect(nginxCrit.capecId).toBe(`${PROJECT_ID}-CAPEC-63`)
  })

  test('killChain: CISA-KEV rows sort before non-KEV at same CVSS tier', async () => {
    const body = await fetchRedZone('killChain')
    // First KEV index must precede any non-KEV with equal-or-higher rank
    const kevRows  = body.rows.filter((r: any) => r.cisaKev)
    const nonKev   = body.rows.filter((r: any) => !r.cisaKev)
    if (kevRows.length > 0 && nonKev.length > 0) {
      const firstKevIdx  = body.rows.findIndex((r: any) => r.cisaKev)
      const firstNonIdx  = body.rows.findIndex((r: any) => !r.cisaKev)
      expect(firstKevIdx).toBeLessThan(firstNonIdx)
    }
    expect(body.meta.kevCount).toBe(kevRows.length)
  })

  test('blastRadius: aggregates CVE count + max CVSS + KEV count per Technology', async () => {
    const body = await fetchRedZone('blastRadius')
    const nginx = body.rows.find((r: any) => r.techName === 'nginx' && r.techVersion === '1.18')
    expect(nginx).toBeDefined()
    expect(nginx.cveCount).toBe(2)                  // 2 seeded CVEs
    expect(nginx.maxCvss).toBeCloseTo(9.8, 1)
    expect(nginx.kevCount).toBe(1)                  // 1 linked ExploitGvm
    expect(nginx.baseUrlCount).toBe(1)              // api.example.com
    expect(nginx.ipCount).toBeGreaterThanOrEqual(1) // at least 1 IP via service/port
    expect(nginx.topCveIds).toEqual(expect.arrayContaining([
      `${PROJECT_ID}-CVE-2023-NGINX-1`,
      `${PROJECT_ID}-CVE-2023-NGINX-2`,
    ]))

    const apache = body.rows.find((r: any) => r.techName === 'apache')
    expect(apache).toBeDefined()
    expect(apache.kevCount).toBe(0)
    expect(apache.cveCount).toBe(1)
  })

  test('blastRadius: nginx (has KEV) sorts before apache (no KEV)', async () => {
    const body = await fetchRedZone('blastRadius')
    const nginxIdx = body.rows.findIndex((r: any) => r.techName === 'nginx')
    const apacheIdx = body.rows.findIndex((r: any) => r.techName === 'apache')
    expect(nginxIdx).toBeLessThan(apacheIdx)
  })

  test('takeover: returns exactly the 3 seeded findings with correct verdict bucketing', async () => {
    const body = await fetchRedZone('takeover')
    expect(body.rows.length).toBe(3)

    const confirmed = body.rows.find((r: any) => r.id === 'takeover_confirmed_1')
    expect(confirmed.hostname).toBe('status.example.com')
    expect(confirmed.cnameTarget).toBe('examplestatus.github.io')
    expect(confirmed.provider).toBe('github-pages')
    expect(confirmed.method).toBe('cname')
    expect(confirmed.verdict).toBe('confirmed')
    expect(confirmed.confidence).toBe(90)
    expect(confirmed.severity).toBe('high')
    expect(confirmed.sources).toEqual(expect.arrayContaining(['subjack', 'nuclei_takeover']))

    expect(body.meta.confirmed).toBe(1)
    expect(body.meta.likely).toBe(1)
    expect(body.meta.manualReview).toBe(1)
  })

  test('takeover: confirmed verdict sorts before likely before manual_review', async () => {
    const body = await fetchRedZone('takeover')
    const verdicts = body.rows.map((r: any) => r.verdict)
    expect(verdicts[0]).toBe('confirmed')
    expect(verdicts[verdicts.length - 1]).toBe('manual_review')
  })

  test('secrets: surfaces Secret nodes attached via BaseURL AND via JsReconFinding', async () => {
    const body = await fetchRedZone('secrets')
    expect(body.rows.length).toBeGreaterThanOrEqual(2)
    const aws = body.rows.find((r: any) => r.id === 'sec-aws-1')
    const gh = body.rows.find((r: any) => r.id === 'sec-gh-1')
    expect(aws).toBeDefined()
    expect(gh).toBeDefined()
    expect(aws.origin).toBe('Secret')             // attached via BaseURL-[:HAS_SECRET]
    expect(gh.origin).toBe('JsReconFinding')      // attached via JsReconFinding-[:HAS_SECRET]
    expect(aws.secretType).toBe('AWS Secret Key')
    expect(aws.keyType).toBe('cloud')
    expect(aws.validationStatus).toBe('validated')
    expect(gh.secretType).toBe('GitHub Token Classic')
    expect(gh.jsFileUrl).toBe('https://api.example.com/app.js')
  })

  test('secrets: validated > format_validated; aws_key sorts ahead of github_token', async () => {
    const body = await fetchRedZone('secrets')
    const awsIdx = body.rows.findIndex((r: any) => r.id === 'sec-aws-1')
    const ghIdx  = body.rows.findIndex((r: any) => r.id === 'sec-gh-1')
    expect(awsIdx).toBeLessThan(ghIdx)
  })

  test('netInitAccess: returns both the Redis port-row and the WAF-bypass vuln-row', async () => {
    const body = await fetchRedZone('netInitAccess')
    const redisRow = body.rows.find((r: any) => r.ipAddress === '203.0.113.20' && r.port === 6379)
    expect(redisRow).toBeDefined()
    expect(redisRow.category).toBe('database')
    expect(redisRow.serviceName).toBe('redis')
    expect(redisRow.subdomains).toContain('cache.example.com')
    expect(redisRow.vulnTags).toContain('redis_no_auth')

    const wafRow = body.rows.find((r: any) => r.ipAddress === '203.0.113.30')
    expect(wafRow).toBeDefined()
    expect(wafRow.vulnTags).toContain('waf_bypass')
    expect(wafRow.isCdn).toBe(true)
  })

  test('graphql: surfaces only is_graphql=true endpoints with all scan flags', async () => {
    const body = await fetchRedZone('graphql')
    expect(body.rows.length).toBe(1)
    const gql = body.rows[0]
    expect(gql.path).toBe('/graphql')
    expect(gql.introspection).toBe(true)
    expect(gql.graphiqlExposed).toBe(true)
    expect(gql.fieldSuggestions).toBe(true)
    expect(gql.getAllowed).toBe(false)
    expect(gql.batching).toBe(true)
    expect(gql.tracing).toBe(false)
    expect(gql.queriesCount).toBe(42)
    expect(gql.mutationsCount).toBe(11)
    expect(gql.subscriptionsCount).toBe(0)
    expect(gql.schemaHash).toBe('sha256:abc123')
    expect(gql.sensitiveFieldsSample).toBe('password, token, apiKey')
    expect(gql.vulnTypes).toContain('graphql_introspection_enabled')
  })

  test('graphql: does NOT leak the non-GraphQL /rest/users endpoint', async () => {
    const body = await fetchRedZone('graphql')
    const rest = body.rows.find((r: any) => r.path === '/rest/users')
    expect(rest).toBeUndefined()
  })
})
