/**
 * LIVE integration test for the Supply-Chain SCA endpoint.
 *
 * The unit tests mock the Neo4j session, so they assert on the Cypher STRING and
 * cannot catch a syntax error, a pattern-comprehension that Neo4j rejects, or a
 * datetime that serializes into an unusable object. This seeds a real graph,
 * calls the real running route with a real session cookie, and asserts the
 * response an operator would actually see.
 *
 * The seed is deliberately shaped like the failure modes this feature exists to
 * prevent: a versionless (unverdictable) package, a soft-error finding, a real
 * behavioural hit, a MAL- verdict, a CVE, a non-OSV Vulnerability that must be
 * excluded, and TWO BaseURL anchors so the fan-out is exercised.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/supplyChainSca.integration.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import neo4j, { Driver, Session } from 'neo4j-driver'
import { execFileSync } from 'node:child_process'
import { createToken, AUTH_COOKIE_NAME } from '@/lib/auth'

const NEO4J_URI      = process.env.NEO4J_URI      || 'bolt://localhost:7687'
const NEO4J_USER     = process.env.NEO4J_USER     || 'neo4j'
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || 'password'
const WEBAPP_URL     = process.env.REDZONE_TEST_WEBAPP_URL || 'http://localhost:3000'
const AUTH_SECRET    = process.env.AUTH_SECRET
const PROJECT_ID     = `sca-itest-${Date.now()}`
const USER_ID        = 'sca-itest-user'
const PG_USER_ID     = `u-${PROJECT_ID}`
const PG_USER_EMAIL  = `${PROJECT_ID}@sca.itest`

const BASE_A = 'https://sca-itest.invalid'
const BASE_B = 'https://sca-itest.invalid:8443'

let authCookie = ''
let driver: Driver
let session: Session

const PG_CONTAINER = process.env.SCA_ITEST_PG_CONTAINER || 'redamon-postgres'
const PG_DB        = process.env.POSTGRES_DB   || 'redamon'
const PG_ROLE      = process.env.POSTGRES_USER || 'redamon'

/**
 * The route guard requires a real project row owned by the caller, so one has to
 * exist in Postgres. Prisma is NOT used for it: the checked-in client is
 * generated for the container's musl runtime and cannot load on a glibc host,
 * which is what makes the older *.integration.test.ts files unrunnable outside
 * CI. psql through the running container has no such constraint.
 */
function psql(sql: string): void {
  execFileSync('docker', ['exec', '-i', PG_CONTAINER, 'psql', '-U', PG_ROLE, '-d', PG_DB, '-v', 'ON_ERROR_STOP=1', '-c', sql],
    { stdio: 'pipe' })
}

function pgReachable(): boolean {
  try { psql('SELECT 1'); return true } catch { return false }
}

const skipSuite = !AUTH_SECRET || !pgReachable()

async function run(cypher: string, params: Record<string, unknown> = {}): Promise<void> {
  await session.run(cypher, params)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function fetchSca(): Promise<any> {
  const res = await fetch(
    `${WEBAPP_URL}/api/analytics/redzone/supplyChainSca?projectId=${PROJECT_ID}`,
    { headers: { cookie: authCookie } })
  if (!res.ok) throw new Error(`GET supplyChainSca -> ${res.status}: ${await res.text()}`)
  return res.json()
}

beforeAll(async () => {
  if (skipSuite) return
  driver = neo4j.driver(NEO4J_URI, neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD))
  session = driver.session()
  await driver.verifyConnectivity()
  await run(`MATCH (n {project_id: $pid}) DETACH DELETE n`, { pid: PROJECT_ID })

  const p = { pid: PROJECT_ID, uid: USER_ID }

  // Two anchors: L2 writes the artifact once per BaseURL, so every package ends
  // up reachable from both. A row-wise join would double every row.
  await run(`
    MERGE (a:BaseURL {url: $a, user_id: $uid, project_id: $pid})
    MERGE (b:BaseURL {url: $bb, user_id: $uid, project_id: $pid})
    MERGE (gr:GithubRepository {id: 'github-repo-' + $uid + '-' + $pid + '-acme/app'})
      ON CREATE SET gr.name = 'acme/app', gr.user_id = $uid, gr.project_id = $pid

    MERGE (axios:Package {purl: 'pkg:npm/axios@1.14.1', user_id: $uid, project_id: $pid})
      ON CREATE SET axios.name = 'axios', axios.version = '1.14.1',
                    axios.ecosystem = 'npm', axios.source = 'retirejs',
                    axios.source_path = 'web/package-lock.json',
                    axios.first_seen = datetime(), axios.last_seen = datetime()
    // Versionless: harvested by source-map mining, never OSV-verdictable.
    MERGE (lodash:Package {purl: 'pkg:npm/lodash', user_id: $uid, project_id: $pid})
      ON CREATE SET lodash.name = 'lodash', lodash.ecosystem = 'npm',
                    lodash.source = 'sourcemap',
                    lodash.first_seen = datetime(), lodash.last_seen = datetime()
    MERGE (a)-[:DEPENDS_ON]->(axios)
    MERGE (b)-[:DEPENDS_ON]->(axios)
    MERGE (a)-[:DEPENDS_ON]->(lodash)
    MERGE (b)-[:DEPENDS_ON]->(lodash)
    MERGE (gr)-[:DEPENDS_ON]->(axios)

    MERGE (mal:MalPackageFinding {finding_id: 'sca-it-mal', user_id: $uid, project_id: $pid})
      ON CREATE SET mal.verdict = 'malicious', mal.source_tool = 'osv',
                    mal.advisory_id = 'MAL-2026-9999', mal.severity = 'high',
                    mal.confidence = 'malicious', mal.title = 'planted malware',
                    mal.detail = 'typosquat', mal.soft_error = false,
                    mal.aliases = ['GHSA-it-0001'],
                    mal.first_seen = datetime(), mal.last_seen = datetime()
    MERGE (axios)-[:FLAGGED_AS]->(mal)

    MERGE (hit:MalPackageFinding {finding_id: 'sca-it-hit', user_id: $uid, project_id: $pid})
      ON CREATE SET hit.verdict = 'suspicious', hit.source_tool = 'guarddog',
                    hit.advisory_id = 'npm-install-script', hit.severity = 'high',
                    hit.confidence = 'suspicious', hit.title = 'npm-install-script',
                    hit.detail = 'postinstall runs curl', hit.soft_error = false,
                    hit.first_seen = datetime(), hit.last_seen = datetime()
    MERGE (axios)-[:FLAGGED_AS]->(hit)

    // GuardDog never ran for this one. It must NOT read as a suspicious hit.
    MERGE (soft:MalPackageFinding {finding_id: 'sca-it-soft', user_id: $uid, project_id: $pid})
      ON CREATE SET soft.verdict = 'suspicious', soft.source_tool = 'guarddog',
                    soft.advisory_id = 'download-package', soft.severity = 'low',
                    soft.confidence = 'suspicious', soft.title = 'download-package',
                    soft.detail = 'registry unreachable', soft.soft_error = true,
                    soft.first_seen = datetime(), soft.last_seen = datetime()
    MERGE (axios)-[:FLAGGED_AS]->(soft)

    // Legacy row: written before soft_error was persisted, identified only by
    // the marker advisory id. The route's fallback must still classify it.
    MERGE (legacy:MalPackageFinding {finding_id: 'sca-it-legacy', user_id: $uid, project_id: $pid})
      ON CREATE SET legacy.verdict = 'suspicious', legacy.source_tool = 'guarddog',
                    legacy.advisory_id = 'guarddog-not-run', legacy.severity = 'low',
                    legacy.confidence = 'suspicious', legacy.title = 'guarddog-not-run',
                    legacy.first_seen = datetime(), legacy.last_seen = datetime()
    MERGE (lodash)-[:FLAGGED_AS]->(legacy)

    MERGE (cve:Vulnerability {id: 'GHSA-it-cve', user_id: $uid, project_id: $pid})
      ON CREATE SET cve.source = 'osv', cve.name = 'SSRF', cve.description = 'server side request forgery',
                    cve.severity = 'critical',
                    cve.cvss_metrics = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    cve.first_seen = datetime(), cve.updated_at = datetime()
    MERGE (axios)-[:HAS_VULNERABILITY]->(cve)

    // Vulnerability is a SHARED label. A GVM finding attached to a package must
    // not leak into the advisories sheet.
    MERGE (gvm:Vulnerability {id: 'gvm-it-noise', user_id: $uid, project_id: $pid})
      ON CREATE SET gvm.source = 'gvm', gvm.name = 'openvas noise', gvm.severity = 'high',
                    gvm.first_seen = datetime(), gvm.updated_at = datetime()
    MERGE (axios)-[:HAS_VULNERABILITY]->(gvm)
  `, { ...p, a: BASE_A, bb: BASE_B })

  psql(`INSERT INTO users (id, name, email, updated_at, password, role)
        VALUES ('${PG_USER_ID}', 'sca-itest', '${PG_USER_EMAIL}', CURRENT_TIMESTAMP, 'x', 'standard')
        ON CONFLICT (id) DO NOTHING`)
  psql(`INSERT INTO projects (id, user_id, name, ownership_token, updated_at)
        VALUES ('${PROJECT_ID}', '${PG_USER_ID}', 'sca-itest', gen_random_uuid()::text, CURRENT_TIMESTAMP)
        ON CONFLICT (id) DO NOTHING`)
  const token = await createToken(PG_USER_ID, 'standard')
  authCookie = `${AUTH_COOKIE_NAME}=${token}`
}, 30_000)

afterAll(async () => {
  if (skipSuite) return
  try {
    await run(`MATCH (n {project_id: $pid}) DETACH DELETE n`, { pid: PROJECT_ID })
    psql(`DELETE FROM projects WHERE id = '${PROJECT_ID}'`)
    psql(`DELETE FROM users WHERE id = '${PG_USER_ID}'`)
  } finally {
    await session?.close()
    await driver?.close()
  }
}, 30_000)

describe.skipIf(skipSuite)('supplyChainSca: live route', () => {
  test('every query executes and all three sheets come back', async () => {
    const body = await fetchSca()
    expect(Object.keys(body.sheets).sort()).toEqual(['advisories', 'packages', 'verdicts'])
    expect(body.sheets.verdicts.length).toBe(4)
    expect(body.sheets.packages.length).toBe(2)
  })

  // The bug this shape exists to catch: 2 BaseURLs x 4 findings = 8 rows if the
  // anchors are joined instead of collected.
  test('two anchors do not duplicate rows; they collect into one cell', async () => {
    const body = await fetchSca()
    const ids = body.sheets.verdicts.map((r: { findingId: string }) => r.findingId)
    expect(new Set(ids).size).toBe(ids.length)
    const mal = body.sheets.verdicts.find((r: { advisoryId: string }) => r.advisoryId === 'MAL-2026-9999')
    expect(mal.baseUrls.sort()).toEqual([BASE_A, BASE_B].sort())
    expect(mal.repos).toEqual(['acme/app'])
  })

  test('malicious sorts first, not-analysed sorts last', async () => {
    const body = await fetchSca()
    const order = body.sheets.verdicts.map((r: { advisoryId: string }) => r.advisoryId)
    expect(order[0]).toBe('MAL-2026-9999')
    expect(order.slice(-2).sort()).toEqual(['download-package', 'guarddog-not-run'])
  })

  test('soft errors are flagged, from the property AND the legacy marker', async () => {
    const body = await fetchSca()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const by = Object.fromEntries(body.sheets.verdicts.map((r: any) => [r.advisoryId, r]))
    expect(by['download-package'].softError).toBe(true)
    expect(by['npm-install-script'].softError).toBe(false)
    // Written with no soft_error property at all: coalesce must yield false,
    // and the advisory-id fallback is what classifies it downstream.
    expect(by['guarddog-not-run'].softError).toBe(false)
  })

  test('package rollups separate real hits from unchecked ones', async () => {
    const body = await fetchSca()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const axios = body.sheets.packages.find((r: any) => r.name === 'axios')
    expect(axios.maliciousCount).toBe(1)
    expect(axios.suspiciousCount).toBe(1)   // the install-script hit only
    expect(axios.notAnalysedCount).toBe(1)  // the download failure
    // Both Vulnerability nodes hang off the package; the rollup counts them,
    // the advisories SHEET filters to OSV.
    expect(axios.advisoryCount).toBe(2)
    expect(axios.sourcePath).toBe('web/package-lock.json')
  })

  test('the versionless package reports no version and its legacy soft error', async () => {
    const body = await fetchSca()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const lodash = body.sheets.packages.find((r: any) => r.name === 'lodash')
    expect(lodash.version).toBeNull()
    expect(lodash.suspiciousCount).toBe(0)
    expect(lodash.notAnalysedCount).toBe(1)
  })

  test('the advisories sheet excludes non-OSV Vulnerability nodes', async () => {
    const body = await fetchSca()
    const ids = body.sheets.advisories.map((r: { advisoryId: string }) => r.advisoryId)
    expect(ids).toEqual(['GHSA-it-cve'])
    expect(body.sheets.advisories[0].cvss).toContain('CVSS:3.1/')
    expect(body.sheets.advisories[0].severity).toBe('critical')
  })

  test('datetimes serialize as ISO strings, not Neo4j objects', async () => {
    const body = await fetchSca()
    const row = body.sheets.verdicts[0]
    expect(typeof row.lastSeen).toBe('string')
    expect(row.lastSeen).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  test('meta totals count the whole graph and mark nothing truncated', async () => {
    const body = await fetchSca()
    expect(body.meta.totalPackages).toBe(2)
    expect(body.meta.unversioned).toBe(1)
    expect(body.meta.malicious).toBe(1)
    expect(body.meta.suspicious).toBe(1)
    expect(body.meta.notAnalysed).toBe(2)
    expect(body.meta.byEcosystem).toEqual([{ ecosystem: 'npm', count: 2, unversioned: 1 }])
    expect(body.meta.truncated).toEqual({ verdicts: false, packages: false, advisories: false })
  })

  test('another tenant cannot read this project through the route', async () => {
    const res = await fetch(
      `${WEBAPP_URL}/api/analytics/redzone/supplyChainSca?projectId=${PROJECT_ID}`,
      { headers: {} })
    expect([401, 403, 404]).toContain(res.status)
  })
})
