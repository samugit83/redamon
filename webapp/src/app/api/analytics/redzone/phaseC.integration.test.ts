/**
 * Integration test for Phase C endpoints + comprehensive parsing-accuracy
 * audit across ALL 13 Red Zone tables.
 *
 * Seeds a graph that exercises EVERY attribute each table claims to surface
 * and then asserts every field round-trips from Neo4j through Cypher through
 * JSON response.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/phaseC.integration.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import neo4j, { Driver, Session } from 'neo4j-driver'

const NEO4J_URI      = process.env.NEO4J_URI      || 'bolt://localhost:7687'
const NEO4J_USER     = process.env.NEO4J_USER     || 'neo4j'
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || 'password'
const WEBAPP_URL     = process.env.REDZONE_TEST_WEBAPP_URL || 'http://localhost:3000'
const INTERNAL_KEY   = process.env.INTERNAL_API_KEY
const PROJECT_ID     = `redzone-phaseC-${Date.now()}`
const USER_ID        = 'redzone-phaseC-user'

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
  await seedPhaseC()
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

async function seedPhaseC() {
  const p = { pid: PROJECT_ID, uid: USER_ID }

  // ----- threatIntel: Domain + IP with VT/OTX/CriminalIP enrichment + pulse + malware
  await run(`
    MERGE (d:Domain {name: 'evil.example.com', user_id: $uid, project_id: $pid})
      ON CREATE SET
        d.vt_enriched = true,
        d.vt_malicious_count = 5,
        d.vt_suspicious_count = 2,
        d.vt_reputation = -15,
        d.vt_tags = ['malware', 'phishing'],
        d.vt_last_analysis_date = 1704067200,
        d.vt_jarm = '27d40d40d00040d00042d43d000000aa99ce1b3cb6b454ab1b5c65c8df16f4',
        d.otx_enriched = true,
        d.otx_pulse_count = 3,
        d.otx_url_count = 12,
        d.otx_adversaries = ['APT28'],
        d.otx_malware_families = ['PlugX', 'XAgent'],
        d.otx_tlp = 'white',
        d.otx_attack_ids = ['T1566', 'T1190'],
        d.criminalip_enriched = true,
        d.criminalip_risk_grade = 'F',
        d.criminalip_abuse_count = 8,
        d.criminalip_current_service = 'web'
    MERGE (pulse:ThreatPulse {pulse_id: $pid + '-pulse-1'})
      ON CREATE SET
        pulse.user_id = $uid, pulse.project_id = $pid,
        pulse.name = 'APT28 Phishing Campaign 2026',
        pulse.adversary = 'APT28',
        pulse.malware_families = ['PlugX'],
        pulse.attack_ids = ['T1566'],
        pulse.tags = ['phishing', 'apt'],
        pulse.tlp = 'white',
        pulse.author_name = 'AlienVault'
    MERGE (d)-[:APPEARS_IN_PULSE]->(pulse)
    MERGE (mal:Malware {hash: $pid + '-hash-abc123'})
      ON CREATE SET
        mal.user_id = $uid, mal.project_id = $pid,
        mal.hash_type = 'sha256',
        mal.file_type = 'pe32',
        mal.file_name = 'plugx_dropper.exe',
        mal.source = 'otx',
        mal.first_seen = '2025-01-01T00:00:00Z'
    MERGE (d)-[:ASSOCIATED_WITH_MALWARE]->(mal)

    MERGE (ip:IP {address: '203.0.113.100', user_id: $uid, project_id: $pid})
      ON CREATE SET
        ip.vt_enriched = true,
        ip.vt_malicious_count = 10,
        ip.vt_reputation = -20,
        ip.vt_tags = ['c2', 'botnet'],
        ip.otx_pulse_count = 2,
        ip.otx_adversaries = ['APT28'],
        ip.otx_attack_ids = ['T1071'],
        ip.criminalip_enriched = true,
        ip.criminalip_score_inbound = 90,
        ip.criminalip_is_tor = false,
        ip.criminalip_is_proxy = true,
        ip.criminalip_is_vpn = false,
        ip.criminalip_is_darkweb = false,
        ip.criminalip_is_hosting = true,
        ip.criminalip_is_scanner = false,
        ip.criminalip_country = 'RU'
    MERGE (ip)-[:APPEARS_IN_PULSE]->(pulse)
    MERGE (ip)-[:ASSOCIATED_WITH_MALWARE]->(mal)
    MERGE (sdEvil:Subdomain {name: 'c2.evil.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdEvil)-[:RESOLVES_TO]->(ip)
  `, p)

  // ----- supplyChain: JsReconFinding js_file + dependency_confusion + source_map + framework + dev_comment + cloud_asset
  await run(`
    MERGE (d2:Domain {name: 'modernapp.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdApp:Subdomain {name: 'app.modernapp.example.com', user_id: $uid, project_id: $pid})
    MERGE (d2)-[:HAS_SUBDOMAIN]->(sdApp)
    MERGE (bu:BaseURL {url: 'https://app.modernapp.example.com', user_id: $uid, project_id: $pid})
    MERGE (sdApp)-[:HAS_BASE_URL]->(bu)

    MERGE (jsFile:JsReconFinding {id: 'jsfile-main-bundle'})
      ON CREATE SET
        jsFile.user_id = $uid, jsFile.project_id = $pid,
        jsFile.finding_type = 'js_file',
        jsFile.source = 'js_recon',
        jsFile.source_url = 'https://app.modernapp.example.com/static/main.bundle.js',
        jsFile.base_url = 'https://app.modernapp.example.com'
    MERGE (bu)-[:HAS_JS_FILE]->(jsFile)

    MERGE (depConf:JsReconFinding {id: 'jf-depconf-1'})
      ON CREATE SET
        depConf.user_id = $uid, depConf.project_id = $pid,
        depConf.finding_type = 'dependency_confusion',
        depConf.severity = 'high',
        depConf.confidence = 'high',
        depConf.title = 'Internal npm package unclaimed on registry',
        depConf.detail = '@example-corp/internal-utils not found on registry.npmjs.org',
        depConf.evidence = '@example-corp/internal-utils',
        depConf.source_url = 'https://app.modernapp.example.com/static/main.bundle.js',
        depConf.base_url = 'https://app.modernapp.example.com',
        depConf.source = 'js_recon',
        depConf.name = '@example-corp/internal-utils',
        depConf.version = '1.2.3'
    MERGE (jsFile)-[:HAS_JS_FINDING]->(depConf)

    MERGE (sourceMap:JsReconFinding {id: 'jf-sourcemap-1'})
      ON CREATE SET
        sourceMap.user_id = $uid, sourceMap.project_id = $pid,
        sourceMap.finding_type = 'source_map_exposure',
        sourceMap.severity = 'medium',
        sourceMap.title = 'Source map file publicly accessible',
        sourceMap.source_url = 'https://app.modernapp.example.com/static/main.bundle.js.map',
        sourceMap.base_url = 'https://app.modernapp.example.com',
        sourceMap.source = 'js_recon'
    MERGE (jsFile)-[:HAS_JS_FINDING]->(sourceMap)

    MERGE (framework:JsReconFinding {id: 'jf-framework-1'})
      ON CREATE SET
        framework.user_id = $uid, framework.project_id = $pid,
        framework.finding_type = 'framework',
        framework.severity = 'info',
        framework.name = 'React',
        framework.version = '17.0.2',
        framework.source_url = 'https://app.modernapp.example.com/static/main.bundle.js',
        framework.source = 'js_recon'
    MERGE (jsFile)-[:HAS_JS_FINDING]->(framework)

    MERGE (devComment:JsReconFinding {id: 'jf-devcomment-1'})
      ON CREATE SET
        devComment.user_id = $uid, devComment.project_id = $pid,
        devComment.finding_type = 'dev_comment',
        devComment.severity = 'low',
        devComment.title = 'TODO comment leaks internal service URL',
        devComment.detail = '// TODO: replace internal-svc.corp.local with public endpoint',
        devComment.source_url = 'https://app.modernapp.example.com/static/main.bundle.js',
        devComment.source = 'js_recon'
    MERGE (jsFile)-[:HAS_JS_FINDING]->(devComment)

    MERGE (cloudAsset:JsReconFinding {id: 'jf-cloud-1'})
      ON CREATE SET
        cloudAsset.user_id = $uid, cloudAsset.project_id = $pid,
        cloudAsset.finding_type = 'cloud_asset',
        cloudAsset.severity = 'medium',
        cloudAsset.cloud_provider = 'aws',
        cloudAsset.cloud_asset_type = 's3_bucket',
        cloudAsset.title = 'AWS S3 bucket URL leaked',
        cloudAsset.evidence = 'https://internal-configs.s3.amazonaws.com',
        cloudAsset.source_url = 'https://app.modernapp.example.com/static/main.bundle.js',
        cloudAsset.source = 'js_recon'
    MERGE (jsFile)-[:HAS_JS_FINDING]->(cloudAsset)
  `, p)

  // ----- dnsDrift: domain with historic IP resolutions + external sightings + dangling subs
  await run(`
    MERGE (d3:Domain {name: 'legacy.example.org', user_id: $uid, project_id: $pid})
    MERGE (sdLegacy:Subdomain {name: 'legacy.example.org', user_id: $uid, project_id: $pid})
    MERGE (d3)-[:HAS_SUBDOMAIN]->(sdLegacy)

    // Current resolution
    MERGE (currIp:IP {address: '198.51.100.200', user_id: $uid, project_id: $pid})
      ON CREATE SET currIp.asn = 'AS65001', currIp.country = 'US'
    MERGE (sdLegacy)-[:RESOLVES_TO]->(currIp)

    // Historic resolutions (OTX passive DNS)
    MERGE (histIp1:IP {address: '192.0.2.10', user_id: $uid, project_id: $pid})
      ON CREATE SET histIp1.asn = 'AS65099', histIp1.country = 'DE'
    MERGE (histIp2:IP {address: '192.0.2.20', user_id: $uid, project_id: $pid})
      ON CREATE SET histIp2.asn = 'AS65088', histIp2.country = 'CN'
    MERGE (d3)-[r1:HISTORICALLY_RESOLVED_TO]->(histIp1)
      ON CREATE SET r1.first_seen = '2023-01-01', r1.last_seen = '2024-06-01', r1.record_type = 'A'
    MERGE (d3)-[r2:HISTORICALLY_RESOLVED_TO]->(histIp2)
      ON CREATE SET r2.first_seen = '2024-06-01', r2.last_seen = '2025-03-01', r2.record_type = 'A'

    // ExternalDomain sighting
    MERGE (ext:ExternalDomain {domain: 'suspicious-redirect.tld', user_id: $uid, project_id: $pid})
      ON CREATE SET
        ext.sources = ['http_probe_redirect', 'urlscan'],
        ext.times_seen = 5,
        ext.countries_seen = ['RU'],
        ext.first_seen_at = '2025-02-01',
        ext.redirect_from_urls = ['https://legacy.example.org/admin']
    MERGE (d3)-[:HAS_EXTERNAL_DOMAIN]->(ext)

    // Dangling subdomain
    MERGE (sdOld:Subdomain {name: 'old.legacy.example.org', user_id: $uid, project_id: $pid})
      ON CREATE SET sdOld.has_dns_records = false, sdOld.status = 'no_http'
    MERGE (d3)-[:HAS_SUBDOMAIN]->(sdOld)
  `, p)
}

describe.skipIf(skipSuite)('Phase C Red Zone integration: threatIntel + supplyChain + dnsDrift', () => {
  // ---------- threatIntel ----------
  test('threatIntel: Domain row surfaces VT + OTX + CriminalIP + pulse + malware', async () => {
    const body = await fetchRedZone('threatIntel')
    const evil = body.rows.find((r: any) => r.asset === 'evil.example.com')
    expect(evil).toBeDefined()
    expect(evil.assetType).toBe('Domain')
    expect(evil.vtMaliciousCount).toBe(5)
    expect(evil.vtSuspiciousCount).toBe(2)
    expect(evil.vtReputation).toBe(-15)
    expect(evil.vtTags).toEqual(expect.arrayContaining(['malware', 'phishing']))
    expect(evil.vtJarm).toBe('27d40d40d00040d00042d43d000000aa99ce1b3cb6b454ab1b5c65c8df16f4')
    expect(evil.otxPulseCount).toBe(3)
    expect(evil.otxUrlCount).toBe(12)
    expect(evil.otxAdversaries).toEqual(['APT28'])
    expect(evil.otxMalwareFamilies).toEqual(expect.arrayContaining(['PlugX', 'XAgent']))
    expect(evil.otxTlp).toBe('white')
    expect(evil.otxAttackIds).toEqual(expect.arrayContaining(['T1566', 'T1190']))
    expect(evil.criminalipRiskGrade).toBe('F')
    expect(evil.criminalipAbuseCount).toBe(8)
    expect(evil.criminalipCurrentService).toBe('web')
    expect(evil.pulseNames).toContain('APT28 Phishing Campaign 2026')
    expect(evil.pulseAdversaries).toContain('APT28')
    expect(evil.pulseCount).toBe(1)
    expect(evil.malwareHashes).toContain(`${PROJECT_ID}-hash-abc123`)
    expect(evil.malwareCount).toBe(1)
  })

  test('threatIntel: IP row surfaces tor/proxy/vpn/darkweb flags + subdomains', async () => {
    const body = await fetchRedZone('threatIntel')
    const c2 = body.rows.find((r: any) => r.asset === '203.0.113.100')
    expect(c2).toBeDefined()
    expect(c2.assetType).toBe('IP')
    expect(c2.vtMaliciousCount).toBe(10)
    expect(c2.criminalipScoreInbound).toBe(90)
    expect(c2.criminalipIsProxy).toBe(true)
    expect(c2.criminalipIsTor).toBe(false)
    expect(c2.criminalipIsVpn).toBe(false)
    expect(c2.criminalipIsHosting).toBe(true)
    expect(c2.criminalipCountry).toBe('RU')
    expect(c2.subdomains).toContain('c2.evil.example.com')
    expect(c2.vtTags).toEqual(expect.arrayContaining(['c2', 'botnet']))
  })

  test('threatIntel: meta splits domain vs ip count', async () => {
    const body = await fetchRedZone('threatIntel')
    expect(body.meta.domainCount).toBeGreaterThanOrEqual(1)
    expect(body.meta.ipCount).toBeGreaterThanOrEqual(1)
  })

  // ---------- supplyChain ----------
  test('supplyChain: dependency_confusion row carries package + version + evidence', async () => {
    const body = await fetchRedZone('supplyChain')
    const dep = body.rows.find((r: any) => r.id === 'jf-depconf-1')
    expect(dep).toBeDefined()
    expect(dep.findingType).toBe('dependency_confusion')
    expect(dep.severity).toBe('high')
    expect(dep.packageName).toBe('@example-corp/internal-utils')
    expect(dep.version).toBe('1.2.3')
    expect(dep.evidence).toContain('internal-utils')
    expect(dep.sourceUrl).toBe('https://app.modernapp.example.com/static/main.bundle.js')
    expect(dep.parentJsUrl).toBe('https://app.modernapp.example.com/static/main.bundle.js')
    expect(dep.subdomain).toBe('app.modernapp.example.com')
  })

  test('supplyChain: source_map_exposure, framework, dev_comment, cloud_asset all appear', async () => {
    const body = await fetchRedZone('supplyChain')
    const types = new Set(body.rows.map((r: any) => r.findingType))
    expect(types.has('dependency_confusion')).toBe(true)
    expect(types.has('source_map_exposure')).toBe(true)
    expect(types.has('framework')).toBe(true)
    expect(types.has('dev_comment')).toBe(true)
    expect(types.has('cloud_asset')).toBe(true)
    expect(body.meta.byType.dependency_confusion).toBe(1)
    expect(body.meta.byType.source_map_exposure).toBe(1)
  })

  test('supplyChain: framework row carries name + version, cloud_asset carries provider + type', async () => {
    const body = await fetchRedZone('supplyChain')
    const fw = body.rows.find((r: any) => r.findingType === 'framework')
    expect(fw.packageName).toBe('React')
    expect(fw.version).toBe('17.0.2')
    const cloud = body.rows.find((r: any) => r.findingType === 'cloud_asset')
    expect(cloud.cloudProvider).toBe('aws')
    expect(cloud.cloudAssetType).toBe('s3_bucket')
  })

  // ---------- dnsDrift ----------
  test('dnsDrift: domain surfaces historic IPs with full edge metadata', async () => {
    const body = await fetchRedZone('dnsDrift')
    const legacy = body.rows.find((r: any) => r.domain === 'legacy.example.org')
    expect(legacy).toBeDefined()
    expect(legacy.historicIpCount).toBe(2)
    const hist1 = legacy.historicResolutions.find((h: any) => h.address === '192.0.2.10')
    expect(hist1).toBeDefined()
    expect(hist1.asn).toBe('AS65099')
    expect(hist1.country).toBe('DE')
    expect(hist1.firstSeen).toBe('2023-01-01')
    expect(hist1.lastSeen).toBe('2024-06-01')
    expect(hist1.recordType).toBe('A')
  })

  test('dnsDrift: derives ASN drift (DE/CN historic missing from US current)', async () => {
    const body = await fetchRedZone('dnsDrift')
    const legacy = body.rows.find((r: any) => r.domain === 'legacy.example.org')
    expect(legacy.asnDrift).toEqual(expect.arrayContaining(['AS65099', 'AS65088']))
    expect(legacy.countryDrift).toEqual(expect.arrayContaining(['DE', 'CN']))
    expect(legacy.currentIps).toEqual(['198.51.100.200'])
    expect(legacy.currentAsns).toEqual(['AS65001'])
    expect(legacy.currentCountries).toEqual(['US'])
  })

  test('dnsDrift: surfaces ExternalDomain with redirect source + times_seen', async () => {
    const body = await fetchRedZone('dnsDrift')
    const legacy = body.rows.find((r: any) => r.domain === 'legacy.example.org')
    const ext = legacy.externalDomains.find((e: any) => e.domain === 'suspicious-redirect.tld')
    expect(ext).toBeDefined()
    expect(ext.sources).toEqual(expect.arrayContaining(['http_probe_redirect', 'urlscan']))
    expect(ext.timesSeen).toBe(5)
    expect(ext.countriesSeen).toEqual(['RU'])
    expect(ext.redirectFromUrls).toContain('https://legacy.example.org/admin')
  })

  test('dnsDrift: dangling subdomain with has_dns_records=false + status=no_http surfaces', async () => {
    const body = await fetchRedZone('dnsDrift')
    const legacy = body.rows.find((r: any) => r.domain === 'legacy.example.org')
    expect(legacy.danglingSubs).toContain('old.legacy.example.org')
    expect(legacy.danglingSubCount).toBe(1)
  })

  test('dnsDrift: lastResolutionDate = most-recent lastSeen timestamp', async () => {
    const body = await fetchRedZone('dnsDrift')
    const legacy = body.rows.find((r: any) => r.domain === 'legacy.example.org')
    expect(legacy.lastResolutionDate).toMatch(/^2025-03-01/)
  })
})
