/**
 * Integration test for Phase B Red Zone endpoints: webInitAccess, paramMatrix,
 * sharedInfra, dnsEmail.
 *
 * Seeds Neo4j with a complete graph topology exercising every property the
 * Phase B Cypher queries navigate, then calls each HTTP endpoint and asserts
 * exact row content.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/phaseB.integration.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import neo4j, { Driver, Session } from 'neo4j-driver'

const NEO4J_URI      = process.env.NEO4J_URI      || 'bolt://localhost:7687'
const NEO4J_USER     = process.env.NEO4J_USER     || 'neo4j'
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || 'password'
const WEBAPP_URL     = process.env.REDZONE_TEST_WEBAPP_URL || 'http://localhost:3000'
const INTERNAL_KEY   = process.env.INTERNAL_API_KEY
const PROJECT_ID     = `redzone-phaseB-${Date.now()}`
const USER_ID        = 'redzone-phaseB-user'

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

const skipSuite = !INTERNAL_KEY

beforeAll(async () => {
  if (skipSuite) return
  driver = neo4j.driver(NEO4J_URI, neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD))
  session = driver.session()
  await driver.verifyConnectivity()
  await run(`MATCH (n {project_id: $pid}) DETACH DELETE n`, { pid: PROJECT_ID })
  await seedGraph()
}, 30_000)

afterAll(async () => {
  if (skipSuite) return
  try {
    await run(`MATCH (n {project_id: $pid}) DETACH DELETE n`, { pid: PROJECT_ID })
  } finally {
    await session?.close()
    await driver?.close()
  }
}, 30_000)

async function seedGraph() {
  const p = { pid: PROJECT_ID, uid: USER_ID }

  // ----- Domain + apex Subdomain + DNS records (for dnsEmail) -----
  await run(`
    MERGE (d:Domain {name: 'example.com', user_id: $uid, project_id: $pid})
      ON CREATE SET
        d.dnssec = 'signedDelegation',
        d.name_servers = ['ns1.example.com', 'ns2.example.com'],
        d.whois_emails = ['abuse@example.com', 'admin@example.com'],
        d.registrar = 'Gandi SAS',
        d.organization = 'Example Inc',
        d.country = 'US',
        d.expiration_date = '2030-01-01T00:00:00Z',
        d.status = ['clientTransferProhibited'],
        d.vt_malicious_count = 0,
        d.otx_pulse_count = 0
    MERGE (apex:Subdomain {name: 'example.com', user_id: $uid, project_id: $pid})
    MERGE (d)-[:HAS_SUBDOMAIN]->(apex)
    MERGE (mxDns:DNSRecord {type: 'MX',  value: 'mx1.example.com.',  subdomain: 'example.com', user_id: $uid, project_id: $pid})
    MERGE (nsDns:DNSRecord {type: 'NS',  value: 'ns1.example.com.',  subdomain: 'example.com', user_id: $uid, project_id: $pid})
    MERGE (spfDns:DNSRecord {type: 'TXT', value: 'v=spf1 include:_spf.google.com -all', subdomain: 'example.com', user_id: $uid, project_id: $pid})
    MERGE (dmarcDns:DNSRecord {type: 'TXT', value: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com', subdomain: 'example.com', user_id: $uid, project_id: $pid})
    MERGE (apex)-[:HAS_DNS_RECORD]->(mxDns)
    MERGE (apex)-[:HAS_DNS_RECORD]->(nsDns)
    MERGE (apex)-[:HAS_DNS_RECORD]->(spfDns)
    MERGE (apex)-[:HAS_DNS_RECORD]->(dmarcDns)
  `, p)

  // ----- Second domain: everything MISSING (SPF/DMARC/DNSSEC), vuln tags present -----
  await run(`
    MERGE (d2:Domain {name: 'naked.example.net', user_id: $uid, project_id: $pid})
      ON CREATE SET d2.dnssec = 'unsigned'
    MERGE (apex2:Subdomain {name: 'naked.example.net', user_id: $uid, project_id: $pid})
    MERGE (d2)-[:HAS_SUBDOMAIN]->(apex2)
    MERGE (spfVuln:Vulnerability {id: 'seccheck_spf_missing_1', project_id: $pid})
      ON CREATE SET
        spfVuln.source = 'security_check', spfVuln.type = 'spf_missing',
        spfVuln.name = 'SPF Record Missing', spfVuln.severity = 'medium',
        spfVuln.domain = 'naked.example.net', spfVuln.user_id = $uid
    MERGE (dmarcVuln:Vulnerability {id: 'seccheck_dmarc_missing_1', project_id: $pid})
      ON CREATE SET
        dmarcVuln.source = 'security_check', dmarcVuln.type = 'dmarc_missing',
        dmarcVuln.name = 'DMARC Record Missing', dmarcVuln.severity = 'medium',
        dmarcVuln.domain = 'naked.example.net', dmarcVuln.user_id = $uid
    MERGE (dnssecVuln:Vulnerability {id: 'seccheck_dnssec_missing_1', project_id: $pid})
      ON CREATE SET
        dnssecVuln.source = 'security_check', dnssecVuln.type = 'dnssec_missing',
        dnssecVuln.name = 'DNSSEC Not Enabled', dnssecVuln.severity = 'low',
        dnssecVuln.domain = 'naked.example.net', dnssecVuln.user_id = $uid
    MERGE (xferVuln:Vulnerability {id: 'seccheck_zone_transfer_1', project_id: $pid})
      ON CREATE SET
        xferVuln.source = 'security_check', xferVuln.type = 'zone_transfer',
        xferVuln.name = 'DNS Zone Transfer Enabled', xferVuln.severity = 'high',
        xferVuln.domain = 'naked.example.net', xferVuln.user_id = $uid
    MERGE (d2)-[:HAS_VULNERABILITY]->(spfVuln)
    MERGE (d2)-[:HAS_VULNERABILITY]->(dmarcVuln)
    MERGE (d2)-[:HAS_VULNERABILITY]->(dnssecVuln)
    MERGE (d2)-[:HAS_VULNERABILITY]->(xferVuln)
  `, p)

  // ----- Web Initial-Access: BaseURL with auth endpoints + security headers + vulns -----
  await run(`
    MERGE (sdApi:Subdomain {name: 'api.example.com', user_id: $uid, project_id: $pid})
    MERGE (bu:BaseURL {url: 'https://api.example.com', user_id: $uid, project_id: $pid})
      ON CREATE SET
        bu.scheme = 'https', bu.host = 'api.example.com',
        bu.status_code = 200, bu.server = 'nginx/1.18'
    MERGE (sdApi)-[:HAS_BASE_URL]->(bu)

    MERGE (epLogin:Endpoint {path: '/login', method: 'POST', baseurl: 'https://api.example.com', user_id: $uid, project_id: $pid})
      ON CREATE SET epLogin.category = 'auth', epLogin.full_url = 'https://api.example.com/login'
    MERGE (epAdmin:Endpoint {path: '/admin/users', method: 'GET', baseurl: 'https://api.example.com', user_id: $uid, project_id: $pid})
      ON CREATE SET epAdmin.category = 'admin'
    MERGE (epUnrelated:Endpoint {path: '/status', method: 'GET', baseurl: 'https://api.example.com', user_id: $uid, project_id: $pid})
    MERGE (bu)-[:HAS_ENDPOINT]->(epLogin)
    MERGE (bu)-[:HAS_ENDPOINT]->(epAdmin)
    MERGE (bu)-[:HAS_ENDPOINT]->(epUnrelated)

    MERGE (hCsp:Header {name: 'Content-Security-Policy', value: "default-src 'self'", baseurl: 'https://api.example.com', user_id: $uid, project_id: $pid, is_security_header: true})
    MERGE (hXfo:Header {name: 'X-Frame-Options',         value: 'DENY',               baseurl: 'https://api.example.com', user_id: $uid, project_id: $pid, is_security_header: true})
    MERGE (bu)-[:HAS_HEADER]->(hCsp)
    MERGE (bu)-[:HAS_HEADER]->(hXfo)

    MERGE (vLogin:Vulnerability {id: 'seccheck_login_no_https_1', project_id: $pid})
      ON CREATE SET
        vLogin.source = 'security_check', vLogin.type = 'login_no_https',
        vLogin.name = 'Login Form Served Over HTTP', vLogin.severity = 'critical',
        vLogin.url = 'https://api.example.com/login', vLogin.matched_at = 'https://api.example.com/login',
        vLogin.user_id = $uid
    MERGE (bu)-[:HAS_VULNERABILITY]->(vLogin)
  `, p)

  // ----- Parameter Matrix: injectable Parameter + AFFECTS_PARAMETER -----
  await run(`
    MERGE (bu:BaseURL {url: 'https://api.example.com', project_id: $pid})
    MERGE (ep:Endpoint {path: '/search', method: 'GET', baseurl: 'https://api.example.com', user_id: $uid, project_id: $pid})
      ON CREATE SET ep.full_url = 'https://api.example.com/search'
    MERGE (bu)-[:HAS_ENDPOINT]->(ep)
    MERGE (pQ:Parameter {name: 'q', position: 'query', endpoint_path: '/search', baseurl: 'https://api.example.com', user_id: $uid, project_id: $pid})
      ON CREATE SET pQ.is_injectable = true, pQ.type = 'string', pQ.sample_value = '<script>'
    MERGE (ep)-[:HAS_PARAMETER]->(pQ)
    MERGE (vXss:Vulnerability {id: 'nuclei_xss_reflected_1', project_id: $pid})
      ON CREATE SET
        vXss.source = 'nuclei', vXss.template_id = 'xss-reflected',
        vXss.name = 'Reflected XSS in q', vXss.severity = 'high',
        vXss.matcher_name = 'word', vXss.fuzzing_method = 'GET', vXss.fuzzing_parameter = 'q',
        vXss.matched_at = 'https://api.example.com/search?q=%3Cscript%3E', vXss.cvss_score = 7.5,
        vXss.is_dast_finding = true, vXss.user_id = $uid
    MERGE (vXss)-[:AFFECTS_PARAMETER]->(pQ)

    MERGE (pId:Parameter {name: 'id', position: 'query', endpoint_path: '/item', baseurl: 'https://api.example.com', user_id: $uid, project_id: $pid})
      ON CREATE SET pId.is_injectable = true, pId.type = 'int', pId.sample_value = '1'
    MERGE (epItem:Endpoint {path: '/item', method: 'GET', baseurl: 'https://api.example.com', user_id: $uid, project_id: $pid})
    MERGE (bu)-[:HAS_ENDPOINT]->(epItem)
    MERGE (epItem)-[:HAS_PARAMETER]->(pId)
  `, p)

  // ----- Shared Infrastructure: shared certificate SAN + shared ASN + shared IP -----
  await run(`
    MERGE (buA:BaseURL {url: 'https://a.example.com', user_id: $uid, project_id: $pid})
    MERGE (buB:BaseURL {url: 'https://b.example.com', user_id: $uid, project_id: $pid})
    MERGE (buC:BaseURL {url: 'https://c.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdA:Subdomain {name: 'a.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdB:Subdomain {name: 'b.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdC:Subdomain {name: 'c.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdA)-[:HAS_BASE_URL]->(buA)
    MERGE (sdB)-[:HAS_BASE_URL]->(buB)
    MERGE (sdC)-[:HAS_BASE_URL]->(buC)

    MERGE (cert:Certificate {subject_cn: '*.example.com', user_id: $uid, project_id: $pid})
      ON CREATE SET
        cert.issuer = "Let's Encrypt Authority X3",
        cert.not_before = '2025-10-01T00:00:00Z',
        cert.not_after = '2026-09-01T00:00:00Z',
        cert.san = ['*.example.com', 'a.example.com', 'b.example.com', 'c.example.com'],
        cert.tls_version = 'TLS 1.3',
        cert.cipher = 'TLS_AES_256_GCM_SHA384'
    MERGE (buA)-[:HAS_CERTIFICATE]->(cert)
    MERGE (buB)-[:HAS_CERTIFICATE]->(cert)

    MERGE (ipShared:IP {address: '198.51.100.5', user_id: $uid, project_id: $pid})
      ON CREATE SET ipShared.asn = 'AS13335', ipShared.country = 'US', ipShared.organization = 'Cloudflare'
    MERGE (sdA)-[:RESOLVES_TO]->(ipShared)
    MERGE (sdB)-[:RESOLVES_TO]->(ipShared)
    MERGE (sdC)-[:RESOLVES_TO]->(ipShared)

    MERGE (ipOther:IP {address: '198.51.100.6', user_id: $uid, project_id: $pid})
      ON CREATE SET ipOther.asn = 'AS13335', ipOther.country = 'US', ipOther.organization = 'Cloudflare'
    MERGE (sdApiShared:Subdomain {name: 'api.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdApiShared)-[:RESOLVES_TO]->(ipOther)
  `, p)
}

describe.skipIf(skipSuite)('Phase B Red Zone integration: live Neo4j + HTTP', () => {
  // ----- dnsEmail -----
  test('dnsEmail: seeded domain with SPF/DMARC/DNSSEC present', async () => {
    const body = await fetchRedZone('dnsEmail')
    const ex = body.rows.find((r: any) => r.domain === 'example.com')
    expect(ex).toBeDefined()
    expect(ex.spfPresent).toBe(true)
    expect(ex.spfStrict).toBe(true)
    expect(ex.dmarcPresent).toBe(true)
    expect(ex.dmarcPolicy).toBe('reject')
    expect(ex.dnssecEnabled).toBe(true)
    expect(ex.dnssecMissing).toBe(false)
    expect(ex.mxCount).toBe(1)
    expect(ex.registrar).toBe('Gandi SAS')
    expect(ex.organization).toBe('Example Inc')
  })

  test('dnsEmail: naked domain with SPF/DMARC/DNSSEC/zone-transfer vuln tags', async () => {
    const body = await fetchRedZone('dnsEmail')
    const naked = body.rows.find((r: any) => r.domain === 'naked.example.net')
    expect(naked).toBeDefined()
    expect(naked.vulnTags).toEqual(expect.arrayContaining([
      'spf_missing', 'dmarc_missing', 'dnssec_missing', 'zone_transfer',
    ]))
    expect(naked.spfMissing).toBe(true)
    expect(naked.dmarcMissing).toBe(true)
    expect(naked.dnssecEnabled).toBe(false)
    expect(naked.zoneTransferOpen).toBe(true)
  })

  // ----- webInitAccess -----
  test('webInitAccess: surfaces BaseURL with auth/admin endpoints', async () => {
    const body = await fetchRedZone('webInitAccess')
    const apiRow = body.rows.find((r: any) => r.baseUrl === 'https://api.example.com')
    expect(apiRow).toBeDefined()
    expect(apiRow.authEndpointCount).toBeGreaterThanOrEqual(2) // /login + /admin
    expect(apiRow.authEndpointPaths).toEqual(expect.arrayContaining(['/login', '/admin/users']))
    expect(apiRow.authCategories).toEqual(expect.arrayContaining(['auth', 'admin']))
  })

  test('webInitAccess: builds header grid (CSP + X-Frame-Options present, others missing)', async () => {
    const body = await fetchRedZone('webInitAccess')
    const apiRow = body.rows.find((r: any) => r.baseUrl === 'https://api.example.com')
    expect(apiRow.headerGrid['Content-Security-Policy']).toBe(true)
    expect(apiRow.headerGrid['X-Frame-Options']).toBe(true)
    expect(apiRow.headerGrid['Strict-Transport-Security']).toBe(false)
    expect(apiRow.headerGrid['X-Content-Type-Options']).toBe(false)
    expect(apiRow.headerGrid['Referrer-Policy']).toBe(false)
    expect(apiRow.headerGrid['Permissions-Policy']).toBe(false)
  })

  test('webInitAccess: login_no_https vuln surfaces via vulnTags', async () => {
    const body = await fetchRedZone('webInitAccess')
    const apiRow = body.rows.find((r: any) => r.baseUrl === 'https://api.example.com')
    expect(apiRow.vulnTags).toContain('login_no_https')
  })

  test('webInitAccess: grade is D (4 missing headers + 1 vuln = 5)', async () => {
    const body = await fetchRedZone('webInitAccess')
    const apiRow = body.rows.find((r: any) => r.baseUrl === 'https://api.example.com')
    expect(apiRow.grade).toBe('D')
  })

  // ----- paramMatrix -----
  test('paramMatrix: injectable param with linked DAST vuln appears with full context', async () => {
    const body = await fetchRedZone('paramMatrix')
    const qRow = body.rows.find((r: any) => r.paramName === 'q' && r.vulnId === 'nuclei_xss_reflected_1')
    expect(qRow).toBeDefined()
    expect(qRow.isInjectable).toBe(true)
    expect(qRow.position).toBe('query')
    expect(qRow.endpointMethod).toBe('GET')
    expect(qRow.endpointPath).toBe('/search')
    expect(qRow.vulnSeverity).toBe('high')
    expect(qRow.vulnSource).toBe('nuclei')
    expect(qRow.templateId).toBe('xss-reflected')
    expect(qRow.cvssScore).toBeCloseTo(7.5, 1)
    expect(qRow.matchedAt).toContain('/search')
  })

  test('paramMatrix: injectable param without vuln still appears (meta.injectableCount)', async () => {
    const body = await fetchRedZone('paramMatrix')
    const idRow = body.rows.find((r: any) => r.paramName === 'id' && r.endpointPath === '/item')
    expect(idRow).toBeDefined()
    expect(idRow.isInjectable).toBe(true)
    expect(idRow.vulnId).toBeNull()
    expect(body.meta.injectableCount).toBeGreaterThanOrEqual(2)
    expect(body.meta.withVulnCount).toBeGreaterThanOrEqual(1)
  })

  // ----- sharedInfra -----
  test('sharedInfra: certificate cluster has 3 subdomains sharing SAN', async () => {
    const body = await fetchRedZone('sharedInfra')
    const certCluster = body.rows.find((r: any) => r.clusterType === 'certificate' && r.certCn === '*.example.com')
    expect(certCluster).toBeDefined()
    expect(certCluster.hostCount).toBeGreaterThanOrEqual(3)
    expect(certCluster.hosts).toEqual(expect.arrayContaining(['a.example.com', 'b.example.com', 'c.example.com']))
    expect(certCluster.tlsVersion).toBe('TLS 1.3')
    expect(certCluster.certIssuer).toContain("Let's Encrypt")
  })

  test('sharedInfra: ASN cluster groups subdomains sharing AS13335', async () => {
    const body = await fetchRedZone('sharedInfra')
    const asnCluster = body.rows.find((r: any) => r.clusterType === 'asn' && r.clusterKey === 'AS13335')
    expect(asnCluster).toBeDefined()
    expect(asnCluster.hostCount).toBeGreaterThanOrEqual(3)
    expect(asnCluster.country).toBe('US')
  })

  test('sharedInfra: IP cluster for shared origin IP', async () => {
    const body = await fetchRedZone('sharedInfra')
    const ipCluster = body.rows.find((r: any) => r.clusterType === 'ip' && r.ipAddress === '198.51.100.5')
    expect(ipCluster).toBeDefined()
    expect(ipCluster.hostCount).toBe(3)
    expect(ipCluster.hosts).toEqual(expect.arrayContaining(['a.example.com', 'b.example.com', 'c.example.com']))
  })

  test('sharedInfra: meta counts each cluster type', async () => {
    const body = await fetchRedZone('sharedInfra')
    expect(body.meta.certClusters).toBeGreaterThanOrEqual(1)
    expect(body.meta.asnClusters).toBeGreaterThanOrEqual(1)
    expect(body.meta.ipClusters).toBeGreaterThanOrEqual(1)
  })
})
